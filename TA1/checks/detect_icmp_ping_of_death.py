import time
from threading import Lock

lock = Lock()

def detect_icmp_ping_of_death(rules, packet_queue, log_alert):
    """Phát hiện các cuộc tấn công ICMP Ping of Death."""
    icmp_rules = [r for r in rules if r["id"] == "ICMP002"]
    while True:
        try:
            time.sleep(5)
            with lock:
                while not packet_queue.empty():
                    packet = packet_queue.get()
                    if packet.haslayer("IP") and packet.haslayer("ICMP"):
                        src_ip = packet["IP"].src
                        packet_size = len(packet)
                        for rule in icmp_rules:
                            max_size = rule["value"].get("packet_size_bytes", 65535)
                            if packet_size > max_size:
                                severity = rule.get("severity", "High")  # Lấy mức độ nguy hiểm từ rule
                                log_alert(
                                    rule["id"],
                                    rule["name"],
                                    src_ip,
                                    f"ICMP packet size: {packet_size} (Max allowed: {max_size})",
                                    severity
                                )
                                print(f"ICMP Ping of Death detected: {rule['name']} - Source IP: {src_ip}, Packet size: {packet_size}, Severity: {severity}")
        except Exception as e:
            print(f"Error in detect_icmp_ping_of_death: {e}")
            time.sleep(1)