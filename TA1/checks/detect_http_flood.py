import time
from threading import Lock

lock = Lock()

def detect_http_flood(rules, http_requests, log_alert):
    """Phát hiện các cuộc tấn công HTTP Flood dựa trên số lượng yêu cầu HTTP từ một IP."""
    httpf_rules = [r for r in rules if r["id"].startswith("HTTPF")]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                for src_ip, count in list(http_requests.items()):
                    for rule in httpf_rules:
                        threshold = rule["value"].get("threshold", 500)
                        if count > threshold:
                            severity = rule.get("severity", "Medium")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"HTTP requests: {count} (Threshold: {threshold})",
                                severity
                            )
                            print(f"HTTP Flood detected: {rule['name']} - Source IP: {src_ip}, Requests: {count}, Severity: {severity}")
                # Xóa các IP đã xử lý để tránh xử lý lại
                http_requests.clear()
        except Exception as e:
            print(f"Error in detect_http_flood: {e}")
            time.sleep(1)