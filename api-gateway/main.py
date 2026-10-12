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
print("Listening for real-time endpoint telemetry on Redis Stream...")

SUSPICIOUS_BINARIES = ['cmd.exe', 'powershell.exe', 'mimikatz.exe', 'nc.exe']

# '$' tells Redis to only read NEW messages that arrive after we connect
last_id = '$'

try:
    while True:
        # Block for up to 1000ms waiting for a new message
        # This allows Ctrl+C to interrupt the loop cleanly every 1 second
        messages = r.xread({'stream:aegis_telemetry': last_id}, count=10, block=1000)
        
        if messages:
            for stream_name, stream_messages in messages:
                for message_id, message_data in stream_messages:
                    # Update last_id to move forward in the stream
                    last_id = message_id
                    
                    try:
                        # The gateway stores the JSON string inside the 'raw_data' key
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
                        print(f"[DEBUG] Malformed JSON received: {message_data}")

except KeyboardInterrupt:
    print("\nShutting down Detection Engine cleanly...")
    sys.exit(0)