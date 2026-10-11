#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include "concurrentqueue.h"

namespace net = boost::asio;
namespace websocket = boost::beast::websocket;
using tcp = boost::asio::ip::tcp;

// Global lock-free queue for raw JSON telemetry strings
moodycamel::ConcurrentQueue<std::string> g_telemetry_queue;
std::atomic<bool> g_running{true};

// Dummy Event Collection Thread (Simulating OS callbacks)
void mock_event_collector(const std::string& agent_id) {
    uint64_t pid_counter = 4000;
    
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        // Formatted per Aegis standardized telemetry schema
        std::string mock_json = "{"
            "\"event_type\": \"process_creation\","
            "\"timestamp\": " + std::to_string(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())) + ","
            "\"agent_id\": \"" + agent_id + "\","
            "\"payload\": {"
                "\"pid\": " + std::to_string(pid_counter++) + ","
                "\"ppid\": 1052,"
                "\"image_path\": \"C:\\\\Windows\\\\System32\\\\cmd.exe\","
                "\"command_line\": \"cmd.exe /c whoami\","
                "\"user\": \"NT AUTHORITY\\\\SYSTEM\","
                "\"hash_sha256\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\""
            "}"
        "}";

        g_telemetry_queue.enqueue(mock_json);
        std::cout << "[Collection Thread] Mock event queued." << std::endl;
    }
}

// Networking Thread consuming queue and transmitting via WebSocket
void network_worker(const std::string& host, const std::string& port, const std::string& agent_id) {
    while (g_running) {
        try {
            net::io_context ioc;
            tcp::resolver resolver(ioc);
            websocket::stream<tcp::socket> ws(ioc);

            auto const results = resolver.resolve(host, port);
            net::connect(ws.next_layer(), results.begin(), results.end());

            std::string target = "/ws/telemetry/" + agent_id;
            ws.handshake(host + ":" + port, target);
            std::cout << "[Network Thread] Connected to API Gateway at " << target << std::endl;

            std::string payload;
            while (g_running) {
                if (g_telemetry_queue.try_dequeue(payload)) {
                    ws.write(net::buffer(payload));
                    std::cout << "[Network Thread] Telemetry transmitted." << std::endl;
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }

            ws.close(websocket::close_code::normal);
        }
        catch (const std::exception& e) {
            std::cerr << "[Network Thread] Connection error: " << e.what() << ". Retrying in 5 seconds..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}

int main() {
    std::string agent_id = "aegis-win-001";
    std::string host = "127.0.0.1";
    std::string port = "8000";

    std::cout << "Starting Aegis Endpoint Agent [" << agent_id << "]..." << std::endl;

    std::thread collector(mock_event_collector, agent_id);
    std::thread network(network_worker, host, port, agent_id);

    collector.join();
    network.join();

    return 0;
}
