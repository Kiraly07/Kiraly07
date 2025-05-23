import time
from threading import Lock

lock = Lock()

def detect_mitm(rules, arp_table, log_alert):
    """Phát hiện các cuộc tấn công Man-in-the-Middle (MITM) dựa trên bảng ARP."""
    mitm_rules = [r for r in rules if r["id"].startswith("MITM")]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                for arp_src_ip, macs in list(arp_table.items()):
                    for rule in mitm_rules:
                        threshold = rule["value"].get("threshold", 1)
                        if len(set(macs)) > threshold:
                            severity = rule.get("severity", "Medium")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                arp_src_ip,
                                f"Multiple MAC addresses detected: {set(macs)} (Threshold: {threshold})",
                                severity
                            )
                            print(f"MITM detected: {rule['name']} - Source IP: {arp_src_ip}, MAC addresses: {set(macs)}, Severity: {severity}")
                            # Xóa các mục đã xử lý để tránh xử lý lại
                            del arp_table[arp_src_ip]
        except KeyError as e:
            print(f"KeyError in detect_mitm: {e}")
        except Exception as e:
            print(f"Error in detect_mitm: {e}")
            time.sleep(1)