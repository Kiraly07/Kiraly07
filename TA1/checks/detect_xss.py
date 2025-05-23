import re
from queue import Empty

def detect_xss(rules, packet_queue, log_alert):
    """Phát hiện các cuộc tấn công XSS dựa trên payload."""
    xss_rules = [r for r in rules if r["id"] == "XSS001"]
    while True:
        try:
            # Lấy gói tin từ hàng đợi
            packet = packet_queue.get(timeout=1)
            if packet.haslayer("Raw"):
                payload = str(packet["Raw"].load, 'utf-8', errors='ignore')
                src_ip = packet["IP"].src if packet.haslayer("IP") else "Unknown"

                # Duyệt qua các quy tắc XSS
                for rule in xss_rules:
                    patterns = rule["value"].get("patterns", [])
                    for pattern in patterns:
                        try:
                            # Sử dụng regex để phát hiện mẫu XSS
                            if re.search(pattern, payload, re.IGNORECASE):
                                severity = rule.get("severity", "Medium")  # Lấy mức độ nguy hiểm từ rule
                                log_alert(
                                    rule["id"],
                                    rule["name"],
                                    src_ip,
                                    f"XSS pattern '{pattern}' detected in payload.",
                                    severity
                                )
                                print(f"XSS detected: {rule['name']} - Source IP: {src_ip}, Pattern: {pattern}, Severity: {severity}")
                        except re.error as e:
                            print(f"Invalid regex pattern '{pattern}' in rule {rule['id']}: {e}")
        except Empty:
            # Không có gói tin trong hàng đợi, tiếp tục vòng lặp
            continue
        except Exception as e:
            print(f"Error in detect_xss: {e}")