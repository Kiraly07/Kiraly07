import time
from threading import Lock

lock = Lock()

def detect_dns_amplification(rules, dns_responses, log_alert):
    """Phát hiện các cuộc tấn công DNS Amplification."""
    dns_rules = [r for r in rules if r["id"] == "DNS001"]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                for src_ip, count in list(dns_responses.items()):
                    for rule in dns_rules:
                        threshold = rule["value"].get("threshold", 1000)
                        if count > threshold:
                            severity = rule.get("severity", "High")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"DNS responses: {count} (Threshold: {threshold})",
                                severity
                            )
                            print(f"DNS Amplification detected: {rule['name']} - Source IP: {src_ip}, Responses: {count}, Severity: {severity}")
                            # Reset bộ đếm sau khi phát hiện
                            dns_responses[src_ip] = 0
        except Exception as e:
            print(f"Error in detect_dns_amplification: {e}")
            time.sleep(1)