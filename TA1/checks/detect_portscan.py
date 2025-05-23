import time
from threading import Lock
from collections import defaultdict

lock = Lock()

def detect_portscan(rules, port_scans, log_alert):
    """Phát hiện các cuộc tấn công Port Scan dựa trên số lượng cổng được quét."""
    portscan_rules = [r for r in rules if r["id"].startswith("PS")]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                for src_ip, ports in list(port_scans.items()):
                    for rule in portscan_rules:
                        threshold = rule["value"].get("threshold", 10)
                        if len(ports) > threshold:
                            severity = rule.get("severity", "Medium")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                src_ip,
                                f"Scanned ports: {len(ports)} (Threshold: {threshold})",
                                severity
                            )
                            print(f"Port Scan detected: {rule['name']} - Source IP: {src_ip}, Scanned Ports: {len(ports)}, Severity: {severity}")
                            # Xóa các IP đã xử lý để tránh xử lý lại
                            del port_scans[src_ip]
        except KeyError as e:
            print(f"KeyError in detect_portscan: {e}")
        except Exception as e:
            print(f"Error in detect_portscan: {e}")
            time.sleep(1)