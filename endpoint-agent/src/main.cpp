#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>
#include <queue>
#include <boost/asio.hpp>
#include <krabs.hpp>

using boost::asio::ip::tcp;

// Thread-safe telemetry queue
std::queue<std::string> telemetry_queue;
std::mutex queue_mutex;

// ETW Event Callback for Process Creation
void on_process_start(const EVENT_RECORD &record, const krabs::schema &schema) {
    try {
        if (schema.event_id() == 1) { // Process Start
            std::wstring image_path = schema.parse<std::wstring>(L"ImageFileName");
            uint32_t process_id = schema.parse<uint32_t>(L"ProcessId");
            uint32_t parent_pid = schema.parse<uint32_t>(L"ParentProcessId");

            std::string path_str(image_path.begin(), image_path.end());

            std::string payload = "{\"event_type\": \"PROCESS_START\", \"pid\": " + 
                                  std::to_string(process_id) + ", \"ppid\": " + 
                                  std::to_string(parent_pid) + ", \"image\": \"" + path_str + "\"}";

            std::lock_guard<std::mutex> lock(queue_mutex);
            telemetry_queue.push(payload);
            std::cout << "[ETW] Process Started: PID " << process_id << " -> " << path_str << "\n";
        }
    } catch (const std::exception &e) {
        std::cerr << "[ETW Parse Error] " << e.what() << "\n";
    }
}

void etw_collector_thread() {
    try {
        krabs::kernel_trace trace(L"AegisETWSession");
        krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
        
        process_provider.add_on_event_callback(on_process_start);
        trace.enable(process_provider);
        
        std::cout << "[ETW Thread] Kernel process tracing active.\n";
        trace.start();
    } catch (const std::exception &e) {
        std::cerr << "[ETW Error] " << e.what() << " (Make sure you are running as Administrator!)\n";
    }
}

void network_worker(const std::string& host, const std::string& port, const std::string& agent_id) {
    boost::asio::io_context ioc;
    tcp::resolver resolver(ioc);

    while (true) {
        try {
            tcp::resolver::results_type endpoints = resolver.resolve(host, port);
            tcp::socket socket(ioc);
            boost::asio::connect(socket, endpoints);

            std::string path = "/ws/telemetry/" + agent_id;
            
            boost::asio::streambuf request;
            std::ostream request_stream(&request);
            request_stream << "GET " << path << " HTTP/1.1\r\n"
                           << "Host: " << host << ":" << port << "\r\n"
                           << "Upgrade: websocket\r\n"
                           << "Connection: Upgrade\r\n"
                           << "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                           << "Sec-WebSocket-Version: 13\r\n\r\n";

            boost::asio::write(socket, request);

            boost::asio::streambuf response;
            boost::asio::read_until(socket, response, "\r\n\r\n");
            std::cout << "[Network Thread] Connected to API Gateway at " << path << "\n";

            while (true) {
                std::string payload;
                {
                    std::lock_guard<std::mutex> lock(queue_mutex);
                    if (!telemetry_queue.empty()) {
                        payload = telemetry_queue.front();
                        telemetry_queue.pop();
                    }
                }

                if (!payload.empty()) {
                    std::string frame;
                    frame.push_back(0x81); // FIN + Text frame
                    size_t length = payload.size();
                    if (length <= 125) {
                        frame.push_back(static_cast<char>(length | 0x80));
                    } else {
                        frame.push_back(static_cast<char>(126 | 0x80));
                        frame.push_back(static_cast<char>((length >> 8) & 0xFF));
                        frame.push_back(static_cast<char>(length & 0xFF));
                    }

                    frame.append(4, 0x00);
                    frame.append(payload);

                    boost::asio::write(socket, boost::asio::buffer(frame));
                    std::cout << "[Network Thread] Telemetry transmitted.\n";
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[Network Thread] Connection error: " << e.what() << ". Retrying in 5 seconds...\n";
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}

int main() {
    std::string agent_id = "aegis-win-001";
    std::cout << "Starting Aegis Endpoint Agent (ETW Enabled) [" << agent_id << "]...\n";

    std::thread etw_thread(etw_collector_thread);
    etw_thread.detach();

    std::thread net_thread(network_worker, "127.0.0.1", "8000", agent_id);
    net_thread.join();

    return 0;
}