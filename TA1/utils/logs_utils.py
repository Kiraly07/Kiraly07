import os
from datetime import datetime

def parse_ids_alerts_log(log_file="./ids_alerts.log"):
    """Parse and analyze data from the log file for the current day."""
    packet_counts = [0] * 24  # Each element represents an hour in the day
    current_date = datetime.now().strftime("%Y-%m-%d")  # Get the current date

    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    # Assume each log line has the format: [YYYY-MM-DD HH:MM:SS] [ALERT] ...
                    timestamp = line.split("]")[0].strip("[")
                    log_date, log_time = timestamp.split(" ")
                    if log_date == current_date:  # Only process logs for the current day
                        hour = int(log_time.split(":")[0])  # Extract the hour from the timestamp
                        packet_counts[hour] += 1
                except Exception as e:
                    print(f"Error parsing log line: {line}, {e}")

    return {
        "labels": [f"{hour}:00" for hour in range(24)],  # Generate hour labels (00:00, 01:00, ...)
        "values": packet_counts
    }

def parse_attack_types(log_file="./ids_alerts.log"):
    """Parse and analyze the number of attack types from the log file."""
    attack_counts = {}  # Dictionary to store the count of each attack type

    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    # Assume each log line has the format: [YYYY-MM-DD HH:MM:SS] [ALERT] Rule <RULE_ID> (<RULE_NAME>) ...
                    rule_name = line.split("(")[1].split(")")[0]  # Extract the attack type name from the log
                    attack_counts[rule_name] = attack_counts.get(rule_name, 0) + 1
                except Exception as e:
                    print(f"Error parsing log line: {line}, {e}")

    return attack_counts

def clear_logs(log_file="./ids_alerts.log"):
    """Clear the IDS alerts log file."""
    try:
        with open(log_file, "w", encoding="utf-8") as f:
            f.truncate(0)  # Truncate file to 0 bytes
        return True
    except Exception as e:
        print(f"Error clearing logs: {str(e)}")
        return False