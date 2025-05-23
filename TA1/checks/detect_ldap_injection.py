import re
from queue import Empty

def detect_ldap_injection(rules, packet_queue, log_alert):
    """Phát hiện các cuộc tấn công LDAP Injection."""
    ldap_rules = [r for r in rules if r["id"] == "LDAP001"]
    while True:
        try:
            packet = packet_queue.get(timeout=1)
            if packet.haslayer("Raw"):
                payload = str(packet["Raw"].load, 'utf-8', errors='ignore')
                src_ip = packet["IP"].src if packet.haslayer("IP") else "Unknown"

                for rule in ldap_rules:
                    patterns = rule["value"].get("patterns", [])
                    for pattern in patterns:
                        if re.search(pattern, payload, re.IGNORECASE):
                            severity = rule.get("severity", "High")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"LDAP Injection pattern '{pattern}' detected in payload.",
                                severity
                            )
                            print(f"LDAP Injection detected: {rule['name']} - Source IP: {src_ip}, Pattern: {pattern}, Severity: {severity}")
        except Empty:
            continue
        except Exception as e:
            print(f"Error in detect_ldap_injection: {e}")