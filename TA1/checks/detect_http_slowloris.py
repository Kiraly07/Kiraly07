import time
from threading import Lock

lock = Lock()

def detect_http_slowloris(rules, http_requests, log_alert):
    """Phát hiện các cuộc tấn công HTTP Slowloris."""
    slowloris_rules = [r for r in rules if r["id"] == "HTTP002"]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                for src_ip, count in list(http_requests.items()):
                    for rule in slowloris_rules:
                        threshold = rule["value"].get("threshold", 100)
                        if count < threshold:  # Slowloris thường có số lượng yêu cầu thấp
                            severity = rule.get("severity", "Medium")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"Incomplete HTTP requests detected: {count} (Threshold: {threshold})",
                                severity
                            )
                            print(f"HTTP Slowloris detected: {rule['name']} - Source IP: {src_ip}, Requests: {count}, Severity: {severity}")
                # Xóa các IP đã xử lý để tránh xử lý lại
                http_requests.clear()
        except Exception as e:
            print(f"Error in detect_http_slowloris: {e}")
            time.sleep(1)