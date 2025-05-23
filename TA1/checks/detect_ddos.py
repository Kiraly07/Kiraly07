import time
from threading import Lock
from collections import defaultdict
from scapy.layers.inet import IP

lock = Lock()

def detect_ddos(rules, packet_counts, log_alert):
    """Phát hiện các cuộc tấn công DDoS dựa trên số lượng gói tin."""
    ddos_rules = [r for r in rules if r["id"].startswith("DDOS")]
    while True:
        try:
            time.sleep(5)  # Kiểm tra mỗi 5 giây
            with lock:
                total_packets = sum(packet_counts.values())
                for rule in ddos_rules:
                    threshold = rule["value"].get("threshold", 1000)
                    if total_packets > threshold:
                        severity = rule.get("severity", "Critical")
                        log_alert(
                            rule["id"],
                            rule["name"],
                            "Multiple IPs",
                            f"Total packets: {total_packets} (Threshold: {threshold})",
                            severity
                        )
                        print(f"DDoS detected: {rule['name']} - Total packets: {total_packets}, Severity: {severity}")
                        # Reset bộ đếm gói tin sau khi phát hiện
                        packet_counts.clear()
        except Exception as e:
            print(f"Error in detect_ddos: {e}")
            time.sleep(1)