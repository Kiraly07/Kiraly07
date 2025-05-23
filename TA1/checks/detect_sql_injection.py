import re
from queue import Empty

def detect_sql_injection(rules, packet_queue, log_alert):
    """Phát hiện các cuộc tấn công SQL Injection dựa trên payload."""
    sql_rules = [r for r in rules if r["id"] == "SQL001"]
    while True:
        try:
            # Lấy gói tin từ hàng đợi
            packet = packet_queue.get(timeout=1)
            if packet.haslayer("Raw"):
                payload = str(packet["Raw"].load, 'utf-8', errors='ignore')
                src_ip = packet["IP"].src if packet.haslayer("IP") else "Unknown"

                # Duyệt qua các quy tắc SQL Injection
                for rule in sql_rules:
                    patterns = rule["value"].get("patterns", [])
                    for pattern in patterns:
                        try:
                            if re.search(pattern, payload, re.IGNORECASE):
                                severity = rule.get("severity", "High")  # Lấy mức độ nguy hiểm từ rule
                                log_alert(
                                    rule["id"],
                                    rule["name"],
                                    src_ip,
                                    f"SQL Injection pattern '{pattern}' detected in payload.",
                                    severity
                                )
                                print(f"SQL Injection detected: {rule['name']} - Source IP: {src_ip}, Pattern: {pattern}, Severity: {severity}")
                        except re.error as e:
                            print(f"Invalid regex pattern '{pattern}' in rule {rule['id']}: {e}")
        except Empty:
            continue
        except Exception as e:
            print(f"Error in detect_sql_injection: {e}")