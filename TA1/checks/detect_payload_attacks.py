import queue
import re
import time
from threading import Lock

lock = Lock()

def escape_regex(pattern):
    """Escape special characters in a regex pattern."""
    return re.escape(pattern)

def detect_payload_attacks(rules, packet_queue, log_alert):
    """Phát hiện các cuộc tấn công dựa trên payload."""
    attack_rules = [
        r for r in rules 
        if r["id"].startswith(("SQL", "XSS", "RCE", "EXP", "BF", "CS"))
    ]
    while True:
        try:
            packet = packet_queue.get(timeout=1)
            if packet.haslayer("Raw"):
                payload = str(packet["Raw"].load, 'utf-8', errors='ignore')
                src_ip = packet["IP"].src if packet.haslayer("IP") else "Unknown"

                for rule in attack_rules:
                    patterns = rule["value"].get("patterns", [])
                    for pattern in patterns:
                        if re.search(pattern, payload, re.IGNORECASE):
                            severity = rule.get("severity", "Medium")
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"Pattern matched: {pattern}",
                                severity
                            )
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Error in detect_payload_attacks: {e}")