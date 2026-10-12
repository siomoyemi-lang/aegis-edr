#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <initguid.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <mutex>
#include <queue>
#include <vector>
#include <climits>
#include <boost/asio.hpp>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

using boost::asio::ip::tcp;

std::queue<std::string> telemetry_queue;
std::mutex queue_mutex;

static const GUID KernelProcessGuid = 
    { 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

static const GUID SessionGuid = 
    { 0x12345678, 0x1234, 0x1234, { 0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc } };

VOID WINAPI ProcessEventRecord(PEVENT_RECORD pEventRecord) {
    if (IsEqualGUID(pEventRecord->EventHeader.ProviderId, KernelProcessGuid)) {
        if (pEventRecord->EventHeader.EventDescriptor.Id == 1) {
            ULONG bufferSize = 0;
            TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
            if (bufferSize > 0) {
                std::vector<BYTE> buffer(bufferSize);
                PTRACE_EVENT_INFO pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());
                if (TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {
                    
                    DWORD pid = 0;
                    DWORD ppid = 0;
                    std::string image_name = "unknown";

                    for (USHORT i = 0; i < pInfo->PropertyCount; i++) {
                        PWSTR propertyName = reinterpret_cast<PWSTR>(reinterpret_cast<PBYTE>(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
                        PROPERTY_DATA_DESCRIPTOR source = { 0 };
                        source.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
                        source.ArrayIndex = ULONG_MAX;

                        if (_wcsicmp(propertyName, L"ProcessID") == 0) {
                            TdhGetProperty(pEventRecord, 0, NULL, 1, &source, sizeof(DWORD), reinterpret_cast<PBYTE>(&pid));
                        }
                        else if (_wcsicmp(propertyName, L"ParentProcessID") == 0) {
                            TdhGetProperty(pEventRecord, 0, NULL, 1, &source, sizeof(DWORD), reinterpret_cast<PBYTE>(&ppid));
                        }
                        else if (_wcsicmp(propertyName, L"ImageName") == 0) {
                            ULONG propSize = 0;
                            if (TdhGetPropertySize(pEventRecord, 0, NULL, 1, &source, &propSize) == ERROR_SUCCESS && propSize > 0) {
                                std::vector<BYTE> imgBuf(propSize);
                                if (TdhGetProperty(pEventRecord, 0, NULL, 1, &source, propSize, imgBuf.data()) == ERROR_SUCCESS) {
                                    image_name = std::string(reinterpret_cast<char*>(imgBuf.data()), propSize);
                                    while (!image_name.empty() && image_name.back() == '\0') {
                                        image_name.pop_back();
                                    }
                                }
                            }
                        }
                    }

                    std::string escaped_image = "";
                    for (char c : image_name) {
                        if (c == '\\') escaped_image += "\\\\";
                        else if (c != '\0') escaped_image += c;
                    }

                    std::string payload = "{\"event_type\": \"PROCESS_START\", \"pid\": " + 
                                          std::to_string(pid) + ", \"ppid\": " + 
                                          std::to_string(ppid) + ", \"image\": \"" + escaped_image + "\"}";

                    std::lock_guard<std::mutex> lock(queue_mutex);
                    telemetry_queue.push(payload);
                    std::cout << "[Native ETW] Process Started: PID " << pid << " -> " << escaped_image << "\n";
                }
            }
        }
    }
}

void etw_collector_thread() {
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    std::vector<BYTE> propBuffer(bufferSize, 0);
    PEVENT_TRACE_PROPERTIES pTraceProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(propBuffer.data());
    
    pTraceProperties->Wnode.BufferSize = bufferSize;
    pTraceProperties->Wnode.Guid = SessionGuid;
    pTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(0, L"AegisModernSession", pTraceProperties, EVENT_TRACE_CONTROL_STOP);

    ZeroMemory(propBuffer.data(), bufferSize);
    pTraceProperties->Wnode.BufferSize = bufferSize;
    pTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pTraceProperties->Wnode.ClientContext = 1;
    pTraceProperties->Wnode.Guid = SessionGuid;
    pTraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    TRACEHANDLE sessionHandle = 0;
    ULONG status = StartTraceW(&sessionHandle, L"AegisModernSession", pTraceProperties);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        std::cerr << "[ETW Error] StartTrace failed: " << status << "\n";
        return;
    }

    status = EnableTraceEx2(sessionHandle, &KernelProcessGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW Error] EnableTraceEx2 failed: " << status << "\n";
        return;
    }

    EVENT_TRACE_LOGFILEW traceLog = { 0 };
    traceLog.LoggerName = const_cast<LPWSTR>(L"AegisModernSession");
    traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLog.EventRecordCallback = (PEVENT_RECORD_CALLBACK)ProcessEventRecord;

    TRACEHANDLE traceHandle = OpenTraceW(&traceLog);
    if (traceHandle == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        std::cerr << "[ETW Error] OpenTrace failed.\n";
        return;
    }

    std::cout << "[ETW Thread] Native kernel process tracing active (Modern).\n";
    ProcessTrace(&traceHandle, 1, NULL, NULL);
    CloseTrace(traceHandle);
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
                    
                    // WebSocket Client MUST mask frames (Bit 7 set to 1 -> 0x80)
                    if (length <= 125) {
                        frame.push_back(static_cast<char>(length | 0x80));
                    } else {
                        frame.push_back(static_cast<char>(126 | 0x80));
                        frame.push_back(static_cast<char>((length >> 8) & 0xFF));
                        frame.push_back(static_cast<char>(length & 0xFF));
                    }

                    // 4-byte Masking Key (Required by RFC 6455)
                    char mask[4] = { 0x12, 0x34, 0x56, 0x78 };
                    frame.append(mask, 4);

                    // XOR the payload with the mask
                    std::string masked_payload = payload;
                    for (size_t i = 0; i < length; ++i) {
                        masked_payload[i] ^= mask[i % 4];
                    }

                    frame.append(masked_payload);

                    boost::asio::write(socket, boost::asio::buffer(frame));
                    std::cout << "[Network Thread] Telemetry transmitted.\n";
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
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
    std::cout << "Starting Aegis Endpoint Agent (Modern ETW) [" << agent_id << "]...\n";

    std::thread etw_thread(etw_collector_thread);
    etw_thread.detach();

    std::thread net_thread(network_worker, "127.0.0.1", "8000", agent_id);
    net_thread.join();

    return 0;
}