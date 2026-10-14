// Aegis Endpoint Agent (Windows)
//
// Threads
//   ETW collector : native Win32 ETW (Microsoft-Windows-Kernel-Process). The callback does no I/O and
//                   takes no locks - it parses, serialises and enqueues onto a lock-free queue.
//   Network       : RFC 6455 WebSocket client. Sends telemetry + command results, reads gateway
//                   frames (text / ping / close) with a poll()-driven loop, reconnects with backoff.
//   Command       : executes KILL_PID (OpenProcess + TerminateProcess) off the network thread.
//
// Config (environment or flags): AEGIS_GATEWAY_HOST / --host, AEGIS_GATEWAY_PORT / --port,
//                                AEGIS_AGENT_ID / --agent-id, AEGIS_AGENT_TOKEN / --token

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <boost/asio.hpp>   // must precede windows.h (pulls in winsock2.h)
#include <windows.h>
#include <initguid.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <bcrypt.h>

#include <atomic>
#include <chrono>
#include <climits>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "concurrentqueue.h"

#ifdef _MSC_VER
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

using boost::asio::ip::tcp;
using moodycamel::ConcurrentQueue;

// ---------------------------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------------------------
namespace {

constexpr size_t kMaxQueuedEvents = 100000;      // bound memory if the gateway is unreachable
constexpr size_t kMaxFramePayload = 1 << 20;     // refuse absurd frames from the server
constexpr size_t kMaxSendBatch = 64;
constexpr USHORT kTdhInTypeUnicodeString = 1;    // TDH_INTYPE_UNICODESTRING / _ANSISTRING (fixed by the TDH ABI;
constexpr USHORT kTdhInTypeAnsiString = 2;       // defined locally because MinGW's tdh.h omits them)

ConcurrentQueue<std::string> g_telemetry;        // ETW callback -> network thread
ConcurrentQueue<std::string> g_results;          // command thread -> network thread
std::atomic<uint64_t> g_dropped{0};
std::atomic<bool> g_running{true};

struct Command {
    DWORD pid;
    std::string alert_id;
};
std::mutex g_cmd_mutex;                          // commands are rare; a mutex + cv is fine here
std::condition_variable g_cmd_cv;
std::deque<Command> g_cmds;

TRACEHANDLE g_session = 0;
constexpr wchar_t kSessionName[] = L"AegisModernSession";

const GUID kKernelProcessGuid =
    {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
const GUID kSessionGuid =
    {0x12345678, 0x1234, 0x1234, {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};

struct Config {
    std::string host = "127.0.0.1";
    std::string port = "8000";
    std::string agent_id;
    std::string token;
};

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------
std::string env_or(const char* name, const std::string& fallback) {
    char buf[512];
    DWORD n = GetEnvironmentVariableA(name, buf, sizeof buf);
    if (n > 0 && n < sizeof buf) return std::string(buf, n);
    return fallback;
}

std::string default_agent_id() {
    std::string host = env_or("COMPUTERNAME", "");
    if (host.empty()) return "aegis-win-001";
    for (char& c : host) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return "aegis-" + host;
}

bool secure_random(void* out, size_t n) {
    return BCryptGenRandom(nullptr, static_cast<PUCHAR>(out), static_cast<ULONG>(n),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

std::string base64(const unsigned char* data, size_t n) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = data[i] << 16;
        if (i + 1 < n) v |= data[i + 1] << 8;
        if (i + 2 < n) v |= data[i + 2];
        out += t[(v >> 18) & 63];
        out += t[(v >> 12) & 63];
        out += (i + 1 < n) ? t[(v >> 6) & 63] : '=';
        out += (i + 2 < n) ? t[v & 63] : '=';
    }
    return out;
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    snprintf(b, sizeof b, "\\u%04x", c);
                    o += b;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

std::string wide_to_utf8(const wchar_t* w, int wlen) {
    if (wlen <= 0) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, out.data(), n, nullptr, nullptr);
    return out;
}

// Minimal, strict extractors for the tiny command JSON the gateway sends.
// Locate `"key"` then `:` then the value; no recursion, no allocation beyond the result.
bool json_find_value(const std::string& j, const char* key, size_t& pos) {
    std::string needle = std::string("\"") + key + "\"";
    size_t p = j.find(needle);
    if (p == std::string::npos) return false;
    p += needle.size();
    while (p < j.size() && (j[p] == ' ' || j[p] == '\t')) ++p;
    if (p >= j.size() || j[p] != ':') return false;
    ++p;
    while (p < j.size() && (j[p] == ' ' || j[p] == '\t')) ++p;
    pos = p;
    return p < j.size();
}

bool json_get_string(const std::string& j, const char* key, std::string& out) {
    size_t p;
    if (!json_find_value(j, key, p) || j[p] != '"') return false;
    size_t e = j.find('"', p + 1);
    if (e == std::string::npos) return false;
    out = j.substr(p + 1, e - p - 1);
    return true;
}

bool json_get_uint(const std::string& j, const char* key, uint32_t& out) {
    size_t p;
    if (!json_find_value(j, key, p)) return false;
    uint64_t v = 0;
    size_t digits = 0;
    while (p < j.size() && j[p] >= '0' && j[p] <= '9' && digits < 10) {
        v = v * 10 + static_cast<uint64_t>(j[p] - '0');
        ++p;
        ++digits;
    }
    if (digits == 0 || v > 0xFFFFFFFFull) return false;
    out = static_cast<uint32_t>(v);
    return true;
}

bool safe_token(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    for (char c : s)
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_')) return false;
    return true;
}

// ---------------------------------------------------------------------------------------------
// ETW collector
// ---------------------------------------------------------------------------------------------
std::string unix_seconds(const LARGE_INTEGER& filetime) {
    // ClientContext=2 below makes ETW stamp events with system time (FILETIME, 100ns since 1601).
    const uint64_t kEpochDiff = 116444736000000000ull;
    uint64_t ft = static_cast<uint64_t>(filetime.QuadPart);
    return std::to_string(ft > kEpochDiff ? (ft - kEpochDiff) / 10000000ull : 0ull);
}

VOID WINAPI ProcessEventRecord(PEVENT_RECORD rec) {
    // Hot path: no I/O, no locks.
    if (!IsEqualGUID(rec->EventHeader.ProviderId, kKernelProcessGuid)) return;
    if (rec->EventHeader.EventDescriptor.Id != 1) return;  // ProcessStart

    ULONG size = 0;
    if (TdhGetEventInformation(rec, 0, nullptr, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER || size == 0) return;
    std::vector<BYTE> buf(size);
    auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(buf.data());
    if (TdhGetEventInformation(rec, 0, nullptr, info, &size) != ERROR_SUCCESS) return;

    DWORD pid = 0, ppid = 0;
    std::string image = "unknown";

    for (ULONG i = 0; i < info->PropertyCount; ++i) {
        const EVENT_PROPERTY_INFO& prop = info->EventPropertyInfoArray[i];
        if (prop.Flags & PropertyStruct) continue;
        auto* name = reinterpret_cast<PCWSTR>(reinterpret_cast<PBYTE>(info) + prop.NameOffset);

        PROPERTY_DATA_DESCRIPTOR d = {};
        d.PropertyName = reinterpret_cast<ULONGLONG>(name);
        d.ArrayIndex = ULONG_MAX;

        if (_wcsicmp(name, L"ProcessID") == 0) {
            TdhGetProperty(rec, 0, nullptr, 1, &d, sizeof(pid), reinterpret_cast<PBYTE>(&pid));
        } else if (_wcsicmp(name, L"ParentProcessID") == 0) {
            TdhGetProperty(rec, 0, nullptr, 1, &d, sizeof(ppid), reinterpret_cast<PBYTE>(&ppid));
        } else if (_wcsicmp(name, L"ImageName") == 0) {
            ULONG psize = 0;
            if (TdhGetPropertySize(rec, 0, nullptr, 1, &d, &psize) != ERROR_SUCCESS || psize == 0) continue;
            std::vector<BYTE> pb(psize);
            if (TdhGetProperty(rec, 0, nullptr, 1, &d, psize, pb.data()) != ERROR_SUCCESS) continue;
            if (prop.nonStructType.InType == kTdhInTypeAnsiString) {
                size_t n = strnlen(reinterpret_cast<char*>(pb.data()), psize);
                image.assign(reinterpret_cast<char*>(pb.data()), n);
            } else {  // kTdhInTypeUnicodeString (UTF-16LE) - convert properly instead of dropping NULs
                int wlen = static_cast<int>(wcsnlen(reinterpret_cast<wchar_t*>(pb.data()), psize / sizeof(wchar_t)));
                std::string u = wide_to_utf8(reinterpret_cast<wchar_t*>(pb.data()), wlen);
                if (!u.empty()) image = std::move(u);
            }
        }
    }

    if (g_telemetry.size_approx() >= kMaxQueuedEvents) {
        g_dropped.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    std::string payload = "{\"event_type\":\"PROCESS_START\",\"timestamp\":" + unix_seconds(rec->EventHeader.TimeStamp) +
                          ",\"pid\":" + std::to_string(pid) + ",\"ppid\":" + std::to_string(ppid) +
                          ",\"image\":\"" + json_escape(image) + "\"}";
    g_telemetry.enqueue(std::move(payload));
}

std::vector<BYTE> make_trace_props(ULONG& total) {
    total = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + 1024);
    std::vector<BYTE> b(total, 0);
    auto* p = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(b.data());
    p->Wnode.BufferSize = total;
    p->Wnode.Guid = kSessionGuid;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 2;  // system time (FILETIME) so we can emit real timestamps
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return b;
}

void stop_trace() {
    ULONG total;
    auto b = make_trace_props(total);
    ControlTraceW(g_session, g_session ? nullptr : kSessionName,
                  reinterpret_cast<PEVENT_TRACE_PROPERTIES>(b.data()), EVENT_TRACE_CONTROL_STOP);
}

void etw_collector_thread() {
    ULONG total;

    // Remove a stale session left behind by a previous crash.
    {
        auto b = make_trace_props(total);
        ControlTraceW(0, kSessionName, reinterpret_cast<PEVENT_TRACE_PROPERTIES>(b.data()), EVENT_TRACE_CONTROL_STOP);
    }

    auto b = make_trace_props(total);
    TRACEHANDLE session = 0;
    ULONG status = StartTraceW(&session, kSessionName, reinterpret_cast<PEVENT_TRACE_PROPERTIES>(b.data()));
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] StartTrace failed (" << status << ")"
                  << (status == ERROR_ACCESS_DENIED ? " - run this agent as Administrator." : "") << "\n";
        g_running = false;
        return;
    }
    g_session = session;

    status = EnableTraceEx2(session, &kKernelProcessGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION, 0, 0, 0, nullptr);
    if (status != ERROR_SUCCESS) {
        std::cerr << "[ETW] EnableTraceEx2 failed (" << status << ")\n";
        stop_trace();
        g_running = false;
        return;
    }

    EVENT_TRACE_LOGFILEW log = {};
    log.LoggerName = const_cast<LPWSTR>(kSessionName);
    log.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = ProcessEventRecord;

    TRACEHANDLE consumer = OpenTraceW(&log);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) {
        std::cerr << "[ETW] OpenTrace failed (" << GetLastError() << ")\n";
        stop_trace();
        g_running = false;
        return;
    }

    std::cout << "[ETW] Kernel process tracing active.\n";
    ProcessTrace(&consumer, 1, nullptr, nullptr);  // blocks until the session is stopped
    CloseTrace(consumer);
    stop_trace();
    g_session = 0;
}

// ---------------------------------------------------------------------------------------------
// Command execution thread
// ---------------------------------------------------------------------------------------------
void queue_result(const Command& c, bool ok, DWORD err) {
    std::string r = std::string("{\"event_type\":\"KILL_RESULT\",\"status\":\"") + (ok ? "SUCCESS" : "FAILED") +
                    "\",\"pid\":" + std::to_string(c.pid) + ",\"error\":" + std::to_string(err);
    if (!c.alert_id.empty()) r += ",\"alert_id\":\"" + c.alert_id + "\"";
    r += "}";
    g_results.enqueue(std::move(r));
}

void command_thread() {
    while (g_running) {
        Command cmd;
        {
            std::unique_lock<std::mutex> lk(g_cmd_mutex);
            g_cmd_cv.wait_for(lk, std::chrono::milliseconds(250), [] { return !g_cmds.empty() || !g_running; });
            if (g_cmds.empty()) continue;
            cmd = std::move(g_cmds.front());
            g_cmds.pop_front();
        }

        if (cmd.pid <= 4 || cmd.pid == GetCurrentProcessId()) {  // Idle/System/ourselves
            std::cerr << "[Command] Refusing to terminate protected PID " << cmd.pid << "\n";
            queue_result(cmd, false, ERROR_ACCESS_DENIED);
            continue;
        }
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, cmd.pid);
        if (!h) {
            DWORD e = GetLastError();
            std::cerr << "[Command] OpenProcess(" << cmd.pid << ") failed: " << e << "\n";
            queue_result(cmd, false, e);
            continue;
        }
        BOOL ok = TerminateProcess(h, 1);
        DWORD e = ok ? 0 : GetLastError();
        CloseHandle(h);
        std::cout << "[Command] KILL_PID " << cmd.pid << (ok ? " -> terminated\n" : " -> failed\n");
        queue_result(cmd, ok != FALSE, e);
    }
}

// ---------------------------------------------------------------------------------------------
// WebSocket (RFC 6455) client
// ---------------------------------------------------------------------------------------------
std::string build_frame(uint8_t opcode, const std::string& payload) {
    std::string f;
    f.reserve(payload.size() + 14);
    f.push_back(static_cast<char>(0x80 | opcode));  // FIN + opcode
    const size_t n = payload.size();
    if (n <= 125) {
        f.push_back(static_cast<char>(0x80 | n));
    } else if (n <= 0xFFFF) {
        f.push_back(static_cast<char>(0x80 | 126));
        f.push_back(static_cast<char>((n >> 8) & 0xFF));
        f.push_back(static_cast<char>(n & 0xFF));
    } else {
        f.push_back(static_cast<char>(0x80 | 127));
        for (int s = 56; s >= 0; s -= 8) f.push_back(static_cast<char>((static_cast<uint64_t>(n) >> s) & 0xFF));
    }
    unsigned char mask[4];  // fresh, unpredictable masking key for every frame (RFC 6455 5.3)
    if (!secure_random(mask, sizeof mask)) throw std::runtime_error("secure RNG unavailable");
    f.append(reinterpret_cast<char*>(mask), 4);
    for (size_t i = 0; i < n; ++i) f.push_back(static_cast<char>(payload[i] ^ mask[i & 3]));
    return f;
}

void handle_gateway_message(const std::string& msg) {
    std::string action;
    if (!json_get_string(msg, "action", action) || action != "KILL_PID") return;
    uint32_t pid;
    if (!json_get_uint(msg, "target", pid)) return;
    Command c{pid, {}};
    std::string alert_id;
    if (json_get_string(msg, "alert_id", alert_id) && safe_token(alert_id)) c.alert_id = alert_id;
    {
        std::lock_guard<std::mutex> lk(g_cmd_mutex);
        g_cmds.push_back(std::move(c));
    }
    g_cmd_cv.notify_one();
}

// Parse as many complete frames as `rx` holds. Returns false if the connection should close.
bool pump_frames(std::string& rx, std::string& partial, uint8_t& partial_op, tcp::socket& sock) {
    for (;;) {
        if (rx.size() < 2) return true;
        const uint8_t b0 = static_cast<uint8_t>(rx[0]), b1 = static_cast<uint8_t>(rx[1]);
        const bool fin = b0 & 0x80;
        const uint8_t op = b0 & 0x0F;
        const bool masked = b1 & 0x80;
        uint64_t len = b1 & 0x7F;
        size_t hdr = 2;
        if (len == 126) {
            if (rx.size() < 4) return true;
            len = (static_cast<uint8_t>(rx[2]) << 8) | static_cast<uint8_t>(rx[3]);
            hdr = 4;
        } else if (len == 127) {
            if (rx.size() < 10) return true;
            len = 0;
            for (int i = 0; i < 8; ++i) len = (len << 8) | static_cast<uint8_t>(rx[2 + i]);
            hdr = 10;
        }
        if (len > kMaxFramePayload) return false;  // protocol abuse
        const size_t mask_len = masked ? 4 : 0;
        if (rx.size() < hdr + mask_len + len) return true;

        std::string payload = rx.substr(hdr + mask_len, static_cast<size_t>(len));
        if (masked)
            for (size_t i = 0; i < payload.size(); ++i) payload[i] ^= rx[hdr + (i & 3)];
        rx.erase(0, hdr + mask_len + static_cast<size_t>(len));

        switch (op) {
            case 0x1:  // text
            case 0x2:  // binary
            case 0x0:  // continuation
                if (op != 0x0) { partial.clear(); partial_op = op; }
                partial += payload;
                if (partial.size() > kMaxFramePayload) return false;
                if (fin) {
                    if (partial_op == 0x1) handle_gateway_message(partial);
                    partial.clear();
                }
                break;
            case 0x9:  // ping -> pong with identical payload
                boost::asio::write(sock, boost::asio::buffer(build_frame(0xA, payload)));
                break;
            case 0xA:  // pong
                break;
            case 0x8:  // close: echo and drop the connection
                try { boost::asio::write(sock, boost::asio::buffer(build_frame(0x8, payload.substr(0, 2)))); } catch (...) {}
                return false;
            default:
                return false;
        }
    }
}

void run_session(const Config& cfg, boost::asio::io_context& ioc) {
    tcp::resolver resolver(ioc);
    tcp::socket sock(ioc);
    boost::asio::connect(sock, resolver.resolve(cfg.host, cfg.port));
    sock.set_option(tcp::no_delay(true));

    unsigned char keyraw[16];
    if (!secure_random(keyraw, sizeof keyraw)) throw std::runtime_error("secure RNG unavailable");
    std::string ws_key = base64(keyraw, sizeof keyraw);

    std::string req = "GET /ws/telemetry/" + cfg.agent_id + " HTTP/1.1\r\n"
                      "Host: " + cfg.host + ":" + cfg.port + "\r\n"
                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Key: " + ws_key + "\r\nSec-WebSocket-Version: 13\r\n";
    if (!cfg.token.empty()) req += "X-Agent-Token: " + cfg.token + "\r\n";
    req += "\r\n";
    boost::asio::write(sock, boost::asio::buffer(req));

    boost::asio::streambuf resp;
    boost::asio::read_until(sock, resp, "\r\n\r\n");
    std::istream is(&resp);
    std::string status_line;
    std::getline(is, status_line);
    if (status_line.find(" 101") == std::string::npos)
        throw std::runtime_error("WebSocket upgrade rejected: " + status_line);
    // Drain the rest of the HTTP headers; anything left in the buffer is already frame data.
    std::string line;
    while (std::getline(is, line) && line != "\r" && !line.empty()) {}
    std::string rx{std::istreambuf_iterator<char>(is), std::istreambuf_iterator<char>()};
    std::string partial;
    uint8_t partial_op = 0;

    std::cout << "[Network] Connected to gateway as " << cfg.agent_id << "\n";

    uint64_t reported_drops = 0;
    while (g_running) {
        // 1) outbound: command results first, then a bounded batch of telemetry
        std::string item;
        while (g_results.try_dequeue(item)) boost::asio::write(sock, boost::asio::buffer(build_frame(0x1, item)));
        size_t sent = 0;
        while (sent < kMaxSendBatch && g_telemetry.try_dequeue(item)) {
            boost::asio::write(sock, boost::asio::buffer(build_frame(0x1, item)));
            ++sent;
        }
        uint64_t d = g_dropped.load(std::memory_order_relaxed);
        if (d != reported_drops) {
            std::cerr << "[Network] Warning: " << (d - reported_drops) << " events dropped (queue full)\n";
            reported_drops = d;
        }

        // 2) inbound: wait (briefly) for data without blocking sends
        WSAPOLLFD pfd = {};
        pfd.fd = sock.native_handle();
        pfd.events = POLLRDNORM;
        int rc = WSAPoll(&pfd, 1, sent == kMaxSendBatch ? 0 : 20);
        if (rc == SOCKET_ERROR) throw std::runtime_error("WSAPoll failed");
        if (rc > 0) {
            char tmp[4096];
            boost::system::error_code ec;
            size_t n = sock.read_some(boost::asio::buffer(tmp), ec);  // readable => will not block
            if (ec || n == 0) throw std::runtime_error("connection closed by gateway");
            rx.append(tmp, n);
            if (!pump_frames(rx, partial, partial_op, sock)) throw std::runtime_error("gateway closed the session");
        }
    }
    try { boost::asio::write(sock, boost::asio::buffer(build_frame(0x8, std::string("\x03\xe8", 2)))); } catch (...) {}
}

void network_worker(Config cfg) {
    boost::asio::io_context ioc;
    int backoff = 1;
    while (g_running) {
        try {
            run_session(cfg, ioc);
            backoff = 1;
        } catch (const std::exception& e) {
            if (!g_running) break;
            std::cerr << "[Network] " << e.what() << " - retrying in " << backoff << "s\n";
        }
        for (int i = 0; i < backoff * 10 && g_running; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        backoff = std::min(backoff * 2, 30);  // exponential backoff, capped
    }
}

BOOL WINAPI console_handler(DWORD) {
    g_running = false;
    g_cmd_cv.notify_all();
    if (g_session) stop_trace();  // unblocks ProcessTrace so the ETW thread can exit
    return TRUE;
}

Config parse_config(int argc, char** argv) {
    Config c;
    c.host = env_or("AEGIS_GATEWAY_HOST", c.host);
    c.port = env_or("AEGIS_GATEWAY_PORT", c.port);
    c.agent_id = env_or("AEGIS_AGENT_ID", "");
    c.token = env_or("AEGIS_AGENT_TOKEN", "");
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string k = argv[i], v = argv[i + 1];
        if (k == "--host") c.host = v;
        else if (k == "--port") c.port = v;
        else if (k == "--agent-id") c.agent_id = v;
        else if (k == "--token") c.token = v;
    }
    if (c.agent_id.empty()) c.agent_id = default_agent_id();
    return c;
}

}  // namespace

int main(int argc, char** argv) {
    Config cfg = parse_config(argc, argv);
    std::cout << "Starting Aegis Endpoint Agent [" << cfg.agent_id << "] -> " << cfg.host << ":" << cfg.port << "\n";
    SetConsoleCtrlHandler(console_handler, TRUE);

    std::thread etw(etw_collector_thread);
    std::thread cmd(command_thread);
    std::thread net(network_worker, cfg);

    net.join();
    g_running = false;
    g_cmd_cv.notify_all();
    if (g_session) stop_trace();
    etw.join();
    cmd.join();
    std::cout << "Aegis agent stopped.\n";
    return 0;
}
