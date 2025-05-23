import time
from threading import Lock

lock = Lock()

def detect_ftp_bruteforce(rules, login_attempts, log_alert):
    """Phát hiện các cuộc tấn công FTP Brute Force."""
    ftp_rules = [r for r in rules if r["id"] == "FTP001"]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                for src_ip, attempts in list(login_attempts.items()):
                    for rule in ftp_rules:
                        threshold = rule["value"].get("threshold", 15)
                        if attempts > threshold:
                            severity = rule.get("severity", "Medium")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"Failed FTP login attempts: {attempts} (Threshold: {threshold})",
                                severity
                            )
                            print(f"FTP Brute Force detected: {rule['name']} - Source IP: {src_ip}, Attempts: {attempts}, Severity: {severity}")
                            # Reset số lần đăng nhập thất bại sau khi phát hiện
                            login_attempts[src_ip] = 0
        except Exception as e:
            print(f"Error in detect_ftp_bruteforce: {e}")
            time.sleep(1)