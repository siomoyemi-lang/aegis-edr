"""Aegis Detection Engine.

Reads endpoint telemetry from the Redis Stream through a consumer group (so no event is lost
while the engine is down and nothing is processed twice), evaluates the declarative rules in
rules.json, publishes alerts, maintains the process cache that powers lineage graphs, and can
optionally dispatch KILL_PID to the gateway.

Environment:
  REDIS_URL             redis://localhost:6379/0
  AEGIS_GATEWAY_URL     http://localhost:8000
  AEGIS_API_KEY         shared secret for the gateway kill endpoint (optional in dev)
  AEGIS_AUTO_KILL       1 to terminate flagged processes automatically (default 0 = alert only)
  AEGIS_AUTO_KILL_MIN_SEVERITY  minimum severity that triggers auto-kill (default CRITICAL)
  AEGIS_RULES_FILE      path to the rules file (default rules.json next to this script)
  AEGIS_CONSUMER        consumer name inside the group (default engine-1)
  AEGIS_LOG_LEVEL       INFO | DEBUG (DEBUG logs every process event)
"""
import json
import logging
import ntpath
import os
import signal
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

import redis

from rules import SEVERITIES, RuleError, RuleSet

HERE = os.path.dirname(os.path.abspath(__file__))
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
GATEWAY_URL = os.getenv("AEGIS_GATEWAY_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.getenv("AEGIS_API_KEY", "")
AUTO_KILL = os.getenv("AEGIS_AUTO_KILL", "0") == "1"
AUTO_KILL_MIN = os.getenv("AEGIS_AUTO_KILL_MIN_SEVERITY", "CRITICAL").upper()
RULES_FILE = os.getenv("AEGIS_RULES_FILE", os.path.join(HERE, "rules.json"))
CONSUMER = os.getenv("AEGIS_CONSUMER", "engine-1")

TELEMETRY_STREAM = "stream:aegis_telemetry"
GROUP = "aegis_detection"
ALERT_CHANNEL = "channel:alerts"
ALERT_STREAM = "stream:aegis_alerts"
PROC_TTL_SECONDS = 24 * 3600
# PIDs are reused by Windows; never act on an event that is older than this (e.g. backlog replay).
AUTO_KILL_MAX_EVENT_AGE_S = 30

logging.basicConfig(
    level=os.getenv("AEGIS_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("aegis.engine")

_running = True


def _stop(signum, _frame):
    global _running
    _running = False
    log.info("Shutdown requested (signal %s)...", signum)


def connect() -> redis.Redis:
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    while _running:
        try:
            r.ping()
            return r
        except redis.ConnectionError:
            log.error("Could not reach Redis at %s - retrying in 3s (is Docker running?)", REDIS_URL)
            time.sleep(3)
    sys.exit(0)


def ensure_group(r: redis.Redis) -> None:
    try:
        # id="0": a brand-new group starts at the beginning so historical backlog is analysed too.
        r.xgroup_create(TELEMETRY_STREAM, GROUP, id="0", mkstream=True)
        log.info("Created consumer group %s", GROUP)
    except redis.ResponseError as e:
        if "BUSYGROUP" not in str(e):
            raise


def normalise(payload: dict, agent_id: str) -> dict:
    image = payload.get("image") or payload.get("image_path") or ""
    return {
        "event_type": payload.get("event_type"),
        "agent_id": agent_id,
        "pid": payload.get("pid"),
        "ppid": payload.get("ppid"),
        "image_path": image,
        "image_name": ntpath.basename(image).lower(),
        "command_line": payload.get("command_line"),
    }


def update_process_cache(r: redis.Redis, event: dict) -> None:
    """Record the process + enrich the event with its parent's image (one pipeline round trip)."""
    aid, pid, ppid = event["agent_id"], event["pid"], event["ppid"]
    record = {
        "agent_id": aid,
        "pid": pid,
        "ppid": ppid,
        "image_path": event["image_path"],
        "image_name": event["image_name"],
        "time": datetime.now(timezone.utc).isoformat(),
    }
    pipe = r.pipeline()
    pipe.get(f"proc:{aid}:{ppid}")
    pipe.setex(f"proc:{aid}:{pid}", PROC_TTL_SECONDS, json.dumps(record))
    pipe.sadd(f"kids:{aid}:{ppid}", pid)
    pipe.expire(f"kids:{aid}:{ppid}", PROC_TTL_SECONDS)
    parent_raw = pipe.execute()[0]
    if parent_raw:
        event["parent_image_name"] = json.loads(parent_raw).get("image_name")


def dispatch_kill(alert: dict) -> None:
    body = json.dumps({"pid": alert["pid"], "alert_id": alert["alert_id"]}).encode()
    req = urllib.request.Request(
        f"{GATEWAY_URL}/api/agents/{alert['agent_id']}/kill",
        data=body,
        headers={"Content-Type": "application/json", **({"X-API-Key": API_KEY} if API_KEY else {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3):
            log.warning("    -> KILL_PID dispatched for PID %s", alert["pid"])
    except urllib.error.HTTPError as e:
        log.error("    -> Kill dispatch rejected by gateway: HTTP %s", e.code)
    except Exception as e:  # network down, timeout...
        log.error("    -> Kill dispatch failed: %s", e)


def raise_alert(r: redis.Redis, rule: dict, event: dict, event_age_s: float) -> None:
    alert = {
        "alert_id": uuid.uuid4().hex,
        "time": datetime.now(timezone.utc).isoformat(),
        "agent_id": event["agent_id"],
        "rule_id": rule["rule_id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "pid": event["pid"],
        "ppid": event["ppid"],
        "image_path": event["image_path"],
        "status": "open",
    }
    pipe = r.pipeline()
    pipe.xadd(ALERT_STREAM, {"alert": json.dumps(alert)}, maxlen=5000, approximate=True)
    pipe.publish(ALERT_CHANNEL, json.dumps({"type": "NEW_ALERT", "payload": alert}))
    pipe.execute()

    log.warning("[!!!] %s [%s] agent=%s pid=%s image=%s", rule["name"], rule["severity"],
                alert["agent_id"], alert["pid"], alert["image_path"])

    if AUTO_KILL and SEVERITIES.index(rule["severity"]) >= SEVERITIES.index(AUTO_KILL_MIN):
        if event_age_s <= AUTO_KILL_MAX_EVENT_AGE_S:
            dispatch_kill(alert)
        else:
            log.warning("    -> Skipping auto-kill: event is %.0fs old (PID may have been reused)", event_age_s)


def process_message(r: redis.Redis, rules: RuleSet, message_id: str, fields: dict) -> None:
    raw = fields.get("raw_data")
    if not raw:
        return
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("Dropping malformed telemetry %s", message_id)
        return
    if payload.get("event_type") != "PROCESS_START" or payload.get("pid") is None:
        return

    event = normalise(payload, fields.get("agent_id", "unknown"))
    update_process_cache(r, event)
    log.debug("Process logged: %s (PID %s)", event["image_name"], event["pid"])

    event_age_s = max(0.0, time.time() - int(message_id.split("-")[0]) / 1000.0)
    for rule in rules.match(event):
        raise_alert(r, rule, event, event_age_s)


def main() -> None:
    try:
        rules = RuleSet.load(RULES_FILE)
    except (OSError, RuleError, json.JSONDecodeError) as e:
        log.error("Cannot load rules from %s: %s", RULES_FILE, e)
        sys.exit(1)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    r = connect()
    ensure_group(r)
    log.info("Aegis Detection Engine started: %d rules, auto-kill %s", len(rules.rules),
             f"ON (>= {AUTO_KILL_MIN})" if AUTO_KILL else "OFF (alert only)")

    # First re-deliver anything this consumer read but never acknowledged (crash recovery),
    # then switch to new messages.
    read_id = "0"
    while _running:
        try:
            resp = r.xreadgroup(GROUP, CONSUMER, {TELEMETRY_STREAM: read_id}, count=100, block=1000)
        except redis.ConnectionError:
            log.error("Lost Redis connection - retrying in 3s")
            time.sleep(3)
            continue
        except redis.ResponseError as e:
            if "NOGROUP" in str(e):  # stream/group was deleted underneath us
                ensure_group(r)
                continue
            raise

        entries = resp[0][1] if resp else []
        if read_id == "0" and not entries:
            read_id = ">"
            continue

        for message_id, fields in entries:
            try:
                process_message(r, rules, message_id, fields)
            except redis.RedisError:
                log.exception("Redis error on %s; leaving it pending for retry", message_id)
                time.sleep(1)
                break
            except Exception:
                log.exception("Unexpected error on %s; acknowledging to avoid a poison loop", message_id)
            r.xack(TELEMETRY_STREAM, GROUP, message_id)

    log.info("Detection Engine stopped cleanly.")


if __name__ == "__main__":
    main()
