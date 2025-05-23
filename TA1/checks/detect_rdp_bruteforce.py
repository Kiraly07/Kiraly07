import time
from threading import Lock

lock = Lock()

def detect_rdp_bruteforce(rules, login_attempts, log_alert):
    """Phát hiện các cuộc tấn công RDP Brute Force."""
    rdp_rules = [r for r in rules if r["id"] == "RDP001"]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                for src_ip, attempts in list(login_attempts.items()):
                    for rule in rdp_rules:
                        threshold = rule["value"].get("threshold", 10)
                        if attempts > threshold:
                            severity = rule.get("severity", "High")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"Failed RDP login attempts: {attempts} (Threshold: {threshold})",
                                severity
                            )
                            print(f"RDP Brute Force detected: {rule['name']} - Source IP: {src_ip}, Attempts: {attempts}, Severity: {severity}")
                            # Reset số lần đăng nhập thất bại sau khi phát hiện
                            login_attempts[src_ip] = 0
        except Exception as e:
            print(f"Error in detect_rdp_bruteforce: {e}")
            time.sleep(1)