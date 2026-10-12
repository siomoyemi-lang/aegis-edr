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

using boost::asio::ip::tcp;

std::queue<std::string> telemetry_queue;
std::mutex queue_mutex;

static const GUID ProcessProviderGuid = 
    { 0x3d6fa8d0, 0xfe05, 0x11d0, { 0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c } };

// Callback when a kernel event is received
VOID WINAPI ProcessEventRecord(PEVENT_RECORD pEventRecord) {
    if (IsEqualGUID(pEventRecord->EventHeader.ProviderId, ProcessProviderGuid) || 
        IsEqualGUID(pEventRecord->EventHeader.ProviderId, SystemTraceControlGuid)) {
        
        // Event ID 1 = Process Start
        if (pEventRecord->EventHeader.EventDescriptor.Id == 1) {
            ULONG bufferSize = 0;
            TdhGetEventInformation(pEventRecord, 0, NULL, NULL, &bufferSize);
            if (bufferSize > 0) {
                std::vector<BYTE> buffer(bufferSize);
                PTRACE_EVENT_INFO pInfo = reinterpret_cast<PTRACE_EVENT_INFO>(buffer.data());
                if (TdhGetEventInformation(pEventRecord, 0, NULL, pInfo, &bufferSize) == ERROR_SUCCESS) {
                    
                    DWORD pid = 0;
                    DWORD ppid = 0;

                    for (USHORT i = 0; i < pInfo->PropertyCount; i++) {
                        PWSTR propertyName = reinterpret_cast<PWSTR>(reinterpret_cast<PBYTE>(pInfo) + pInfo->EventPropertyInfoArray[i].NameOffset);
                        if (_wcsicmp(propertyName, L"ProcessId") == 0) {
                            PROPERTY_DATA_DESCRIPTOR source = { 0 };
                            source.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
                            source.ArrayIndex = ULONG_MAX;
                            TdhGetProperty(pEventRecord, 0, NULL, 1, &source, sizeof(DWORD), reinterpret_cast<PBYTE>(&pid));
                        }
                        if (_wcsicmp(propertyName, L"ParentProcessId") == 0) {
                            PROPERTY_DATA_DESCRIPTOR source = { 0 };
                            source.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
                            source.ArrayIndex = ULONG_MAX;
                            TdhGetProperty(pEventRecord, 0, NULL, 1, &source, sizeof(DWORD), reinterpret_cast<PBYTE>(&ppid));
                        }
                    }

                    std::string payload = "{\"event_type\": \"PROCESS_START\", \"pid\": " + 
                                          std::to_string(pid) + ", \"ppid\": " + 
                                          std::to_string(ppid) + ", \"image\": \"C:\\Windows\\System32\\cmd.exe\"}";

                    std::lock_guard<std::mutex> lock(queue_mutex);
                    telemetry_queue.push(payload);
                    std::cout << "[Native ETW] Process Started: PID " << pid << ", PPID " << ppid << "\n";
                }
            }
        }
    }
}

void etw_collector_thread() {
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    std::vector<BYTE> propBuffer(bufferSize, 0);
    PEVENT_TRACE_PROPERTIES pTraceProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(propBuffer.data());
    
    // 1. Stop any ghost sessions before starting (prevents Error 183)
    pTraceProperties->Wnode.BufferSize = bufferSize;
    pTraceProperties->Wnode.Guid = SystemTraceControlGuid;
    pTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    ControlTraceW(0, KERNEL_LOGGER_NAMEW, pTraceProperties, EVENT_TRACE_CONTROL_STOP);

    // 2. Re-initialize properties for a fresh trace
    ZeroMemory(propBuffer.data(), bufferSize);
    pTraceProperties->Wnode.BufferSize = bufferSize;
    pTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pTraceProperties->Wnode.ClientContext = 1;
    pTraceProperties->Wnode.Guid = SystemTraceControlGuid;
    pTraceProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // REQUIRED for Error 87
    pTraceProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    pTraceProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // 3. Start Trace (MUST use KERNEL_LOGGER_NAMEW)
    TRACEHANDLE sessionHandle = 0;
    ULONG status = StartTraceW(&sessionHandle, KERNEL_LOGGER_NAMEW, pTraceProperties);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        std::cerr << "[ETW Error] StartTrace failed with error: " << status << " (Run as Administrator!)\n";
        return;
    }

    // 4. Open Real-Time Trace
    EVENT_TRACE_LOGFILEW traceLog = { 0 };
    traceLog.LoggerName = const_cast<LPWSTR>(KERNEL_LOGGER_NAMEW);
    traceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLog.EventRecordCallback = (PEVENT_RECORD_CALLBACK)ProcessEventRecord;

    TRACEHANDLE traceHandle = OpenTraceW(&traceLog);
    if (traceHandle == (TRACEHANDLE)INVALID_HANDLE_VALUE) {
        std::cerr << "[ETW Error] OpenTrace failed.\n";
        return;
    }

    std::cout << "[ETW Thread] Native kernel process tracing active.\n";
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
                    frame.push_back(0x81); 
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
    std::cout << "Starting Aegis Endpoint Agent (Native ETW) [" << agent_id << "]...\n";

    std::thread etw_thread(etw_collector_thread);
    etw_thread.detach();

    std::thread net_thread(network_worker, "127.0.0.1", "8000", agent_id);
    net_thread.join();

    return 0;
}