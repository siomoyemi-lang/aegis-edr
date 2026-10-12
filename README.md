# Aegis EDR

**Aegis** is a production-grade Endpoint Detection and Response (EDR) platform engineered with a strict split-brain architecture. It captures native Windows kernel telemetry at the endpoint with near-zero overhead, offloading all heavy threat analysis, heuristic evaluation, and state management to a centralized, high-throughput backend infrastructure.

## 🏗️ System Architecture

Aegis decouples endpoint collection from threat detection to ensure endpoint stability and prevent localized bypasses. The platform operates across four primary modules:

1. **Endpoint Agent:** A C++20 daemon that hooks directly into the native Win32 ETW (Event Tracing for Windows) API to monitor process creation. It transmits telemetry and listens for Active Response commands over an RFC 6455-compliant masked WebSocket.
2. **API Gateway:** A Python FastAPI asynchronous router capable of maintaining thousands of concurrent agent WebSocket tunnels.
3. **Data Broker:** A Dockerized Redis Streams message broker that ingests telemetry via `XADD` in O(1) time, preventing data loss during traffic spikes or engine downtime.
4. **Detection Engine:** A Python analysis worker that continuously polls the Redis Stream via `XREAD`, evaluates process execution heuristics, and automatically dispatches remediation signals.

## ✨ Core Features

* **Native Kernel Tracing:** Bypasses heavy third-party wrappers by directly subscribing to the `Microsoft-Windows-Kernel-Process` ETW provider for memory-safe extraction of `ProcessID`, `ParentProcessID`, and `ImageName`.
* **Active Response (Kill-Switch):** Bidirectional WebSocket communication enables the Detection Engine to route `KILL_PID` commands back to the C++ agent, executing the Win32 `TerminateProcess` API within milliseconds of a threat spawning.
* **Stream-Based Ingestion:** Transitions away from volatile Pub/Sub models to persistent Redis Streams, ensuring sequential queuing and historical backlog processing.
* **RFC 6455 Security Compliance:** Custom C++ WebSocket framer applies strict 4-byte XOR masking keys to all outbound telemetry payloads.

## 💻 Technology Stack

* **Endpoint Agent:** C++20, Boost.Asio, Win32 API (`evntrace.h`, `tdh.h`), CMake
* **API Gateway:** Python 3.13, FastAPI, Uvicorn, WebSockets
* **Message Broker:** Redis Streams (Docker)
* **Detection Engine:** Python 3.13, Redis Client

## 🚀 Quick Start

### Prerequisites
* Windows 10/11 with Administrator privileges (required for ETW kernel tracing)
* Visual Studio Build Tools (MSVC) & CMake
* Python 3.13+
* Docker Desktop

### ⚡ One-Line Automated Launch

Run the following command in an **Administrator PowerShell** terminal from the project root to spin up the Docker containers, launch the Python Detection Engine in a dedicated background window, compile the C++ Agent, and start live telemetry tracing:

```powershell
docker compose up -d --build; Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PWD'; python detection-engine/main.py"; cmake --build build --config Release; if ($?) { .\build\Release\aegis_agent.exe }
Manual Step-by-Step Launch
If you prefer to run each component in separate terminal windows:

Start Infrastructure (Docker):

PowerShell
docker compose up -d --build
Start Detection Engine:

PowerShell
python detection-engine/main.py
Build & Run Endpoint Agent (Admin PowerShell):

PowerShell
cmake --build build --config Release ; if ($?) { .\build\Release\aegis_agent.exe }
🗺️ Project Roadmap
[x] Phase 1 & 2: API Gateway & Core Threading Model

[x] Phase 3: Native Win32 ETW OS Telemetry

[x] Phase 4: Redis Stream Threat Detection Engine

[x] Phase 5: Active Response (Automated Process Termination)

[ ] Phase 6: React & Next.js SOC Analyst Dashboard (Upcoming)

[ ] Phase 7: Command-Line Argument Extraction & Advanced Sigma Rules

👤 Author
Lead Engineer: Shittu Ibraheem Omoyemi

GitHub: @siomoyemi-lang
