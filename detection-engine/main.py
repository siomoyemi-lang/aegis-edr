import json
import redis
import sys

try:
    # Connect to the local Redis container
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)
    r.ping()
except redis.ConnectionError:
    print("[-] Fatal: Could not connect to Redis. Ensure the Docker container is running.")
    sys.exit(1)

print("Starting Aegis Detection Engine...")
print("Listening for live real-time endpoint telemetry on Redis Stream...")

SUSPICIOUS_BINARIES = ['cmd.exe', 'powershell.exe', 'mimikatz.exe', 'nc.exe']

# '$' tells Redis to ONLY read new messages that arrive after we connect
last_id = '$'

try:
    while True:
        # Read from the stream
        messages = r.xread({'stream:aegis_telemetry': last_id}, count=50, block=1000)
        
        if messages:
            for stream_name, stream_messages in messages:
                for message_id, message_data in stream_messages:
                    # Update last_id so we don't read the same message twice
                    last_id = message_id
                    
                    try:
                        raw_data = message_data.get('raw_data')
                        if not raw_data:
                            continue
                            
                        payload = json.loads(raw_data)
                        
                        if payload.get("event_type") == "PROCESS_START":
                            image_path = payload.get("image", "").lower()
                            pid = payload.get("pid")
                            agent_id = message_data.get("agent_id", "unknown")
                            
                            is_suspicious = any(susp in image_path for susp in SUSPICIOUS_BINARIES)
                            
                            if is_suspicious:
                                print(f"\n[!!!] THREAT DETECTED: Suspicious process spawned!")
                                print(f"      -> Agent: {agent_id}")
                                print(f"      -> Image: {payload.get('image')}")
                                print(f"      -> PID:   {pid}")
                            else:
                                exe_name = image_path.split('\\')[-1]
                                print(f"[*] Process Logged: {exe_name} (PID: {pid})")

                    except json.JSONDecodeError:
                        pass

except KeyboardInterrupt:
    print("\nShutting down Detection Engine cleanly...")
    sys.exit(0)