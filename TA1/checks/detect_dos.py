import time
from threading import Lock

lock = Lock()

def detect_dos(rules, packet_counts, log_alert):
    """Phát hiện các cuộc tấn công DoS dựa trên số lượng gói tin từ một IP."""
    dos_rules = [r for r in rules if r["id"].startswith("DOS")]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                for src_ip, count in list(packet_counts.items()):
                    for rule in dos_rules:
                        threshold = rule["value"].get("threshold", 100)
                        if count > threshold:
                            severity = rule.get("severity", "High")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"Packet count: {count} (Threshold: {threshold})",
                                severity
                            )
                            print(f"DoS detected: {rule['name']} - Source IP: {src_ip}, Packet count: {count}, Severity: {severity}")
                # Xóa các IP đã kiểm tra để tránh xử lý lại
                packet_counts.clear()
        except Exception as e:
            print(f"Error in detect_dos: {e}")
            time.sleep(1)