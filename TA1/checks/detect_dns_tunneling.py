def detect_dns_tunneling(packets, rules, log_alert):
    """Phát hiện các cuộc tấn công DNS Tunneling dựa trên các mẫu truy vấn DNS."""
    for packet in packets:
        if packet.haslayer("DNS") and packet["DNS"].qd:
            query_name = packet["DNS"].qd.qname.decode()
            for rule in rules:
                if rule["id"] == "DNS002":  # Sử dụng ID quy tắc cho DNS Tunneling
                    patterns = rule["value"].get("patterns", [])
                    for pattern in patterns:
                        if pattern in query_name:
                            severity = rule.get("severity", "High")  # Lấy mức độ nguy hiểm từ rule
                            log_alert(
                                rule["id"],
                                rule["name"],
                                packet["IP"].src if packet.haslayer("IP") else "Unknown",
                                f"DNS tunneling pattern '{pattern}' detected in query '{query_name}'.",
                                severity
                            )
                            print(f"DNS Tunneling detected: {rule['name']} - Query: {query_name}, Pattern: {pattern}, Severity: {severity}")