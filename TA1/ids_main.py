import json
import os
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSRR  # Ensure scapy is installed
from datetime import datetime
from threading import Thread, Lock
from collections import defaultdict
import time
import queue
import requests
from utils.telegram_utils import send_telegram_alert  # Import hàm từ file mới

from checks.detect_portscan import detect_portscan
from checks.detect_dos import detect_dos
from checks.detect_ddos import detect_ddos
from checks.detect_payload_attacks import detect_payload_attacks
from checks.detect_mitm import detect_mitm
from checks.detect_http_flood import detect_http_flood
from checks.detect_ftp_bruteforce import detect_ftp_bruteforce
from checks.detect_smtp_relay import detect_smtp_relay
from checks.detect_dns_amplification import detect_dns_amplification
from checks.detect_ssh_bruteforce import detect_ssh_bruteforce
from checks.detect_telnet_bruteforce import detect_telnet_bruteforce
from checks.detect_http_slowloris import detect_http_slowloris
from checks.detect_icmp_ping_of_death import detect_icmp_ping_of_death
from checks.detect_ldap_injection import detect_ldap_injection
from checks.detect_snmp_bruteforce import detect_snmp_bruteforce
from checks.detect_rdp_bruteforce import detect_rdp_bruteforce


# Load configuration from config.json
CONFIG_FILE = "./config.json"
try:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        config = json.load(f)
except FileNotFoundError:
    print(f"Error: {CONFIG_FILE} not found. Exiting.")
    exit(1)
except json.JSONDecodeError:
    print(f"Error: Invalid JSON format in {CONFIG_FILE}. Exiting.")
    exit(1)

# Configuration
INTERFACE = config["ids_config"]["network_interfaces"][0]["interface_name"]
ENABLE_LOGGING = True
LOG_FILE = config["ids_config"].get("logging", {}).get("log_file", "./ids_alerts.log")  # Fallback to default log file

# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN = config["ids_config"]["token_telegram"]["TELEGRAM_BOT_TOKEN"]
TELEGRAM_CHAT_ID = config["ids_config"]["token_telegram"]["TELEGRAM_CHAT_ID"]
TELEGRAM_ALERTS_ENABLED = config["ids_config"]["alerting"]["telegram_alerts"]["enabled"]  # Use updated config

# State variables
port_scans = defaultdict(set)  # Lưu các cổng được quét theo IP
packet_counts = defaultdict(int)  # Đếm số lượng gói tin theo IP
arp_table = defaultdict(list)  # Lưu bảng ARP theo IP
dns_responses = defaultdict(int)  # Đếm số lượng phản hồi DNS theo IP
http_requests = defaultdict(int)  # Đếm số lượng yêu cầu HTTP theo IP
login_attempts = defaultdict(int)  # Đếm số lần đăng nhập thất bại theo IP
packet_queue = queue.Queue()  # Hàng đợi để xử lý gói tin
lock = Lock()

# Utility functions
def load_rules():
    """Load detection rules from a JSON file."""
    try:
        with open("./rules.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print("Error: rules.json not found.")
        return []
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in rules.json.")
        return []

def log_alert_to_file(rule_id, attack_name, src_ip, details="", severity="Medium"):
    """Log alerts to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] [ALERT] Rule {rule_id} ({attack_name}) detected from {src_ip} | Severity: {severity} | Details: {details}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_message)
        print(f"Log written to file: {LOG_FILE}")  # Debug message
    except PermissionError:
        print(f"Permission error: Cannot write to log file {LOG_FILE}.")
    except FileNotFoundError:
        print(f"File not found: Log file {LOG_FILE} does not exist.")
    except Exception as e:
        print(f"Error writing to log file {LOG_FILE}: {e}")

def log_alert(rule_id, attack_name, src_ip, details="", severity="Medium"):
    """Log alerts to the console, file, and Telegram."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console_message = f"[{timestamp}] [ALERT] Rule {rule_id} ({attack_name}) detected from {src_ip} | Severity: {severity} | Details: {details}"
    print(console_message)
    if ENABLE_LOGGING:
        log_alert_to_file(rule_id, attack_name, src_ip, details, severity)
    # Send alert to Telegram
    if TELEGRAM_ALERTS_ENABLED:
        try:
            print(f"[DEBUG] Sending Telegram alert: {console_message}")  # Debug message
            send_telegram_alert(console_message)
            print("[SUCCESS] Telegram alert sent successfully.")  # Debug message
        except Exception as e:
            print(f"[ERROR] Failed to send Telegram alert: {e}")
            print(f"[DEBUG] Check TELEGRAM_BOT_TOKEN: {TELEGRAM_BOT_TOKEN} and TELEGRAM_CHAT_ID: {TELEGRAM_CHAT_ID}")  # Debug info

# Packet processing
def process_packet(packet):
    """Process incoming packets and update state variables."""
    try:
        if packet.haslayer(IP):  # Check if the packet has an IP layer
            src_ip = packet[IP].src
            with lock:
                packet_counts[src_ip] += 1
                if packet.haslayer(TCP):
                    port_scans[src_ip].add(packet[TCP].dport)  # Add destination port
                if packet.haslayer(scapy.ARP):
                    arp_table[packet[scapy.ARP].psrc].append(packet[scapy.ARP].hwsrc)  # Add ARP source
                if packet.haslayer(DNSRR):
                    dns_responses[src_ip] += 1  # Increment DNS response count
                if packet.haslayer(HTTPRequest):
                    http_requests[src_ip] += 1
            if packet.haslayer(scapy.Raw) or packet.haslayer(DNSRR):
                packet_queue.put(packet)
    except Exception as e:
        print(f"Error processing packet: {e}")

def sniff_packets():
    """Capture packets from the specified network interface."""
    print(f"Starting IDS on interface {INTERFACE}...")
    while True:
        try:
            scapy.sniff(iface=INTERFACE, prn=process_packet, store=False, timeout=300)
            print("Sniffing paused, restarting in 5 seconds...")
            time.sleep(5)
        except Exception as e:
            print(f"Error in sniff_packets: {e}")
            print("Retrying in 5 seconds...")
            time.sleep(5)

# Main function
def main():
    global ENABLE_LOGGING  # Khai báo ENABLE_LOGGING là biến toàn cục

    # Check network interface
    available_interfaces = scapy.get_if_list()
    if INTERFACE not in available_interfaces:
        print(f"Error: Interface {INTERFACE} not found. Available interfaces: {available_interfaces}")
        return

    # Check log file permissions
    if ENABLE_LOGGING:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                pass
            print(f"Log file {LOG_FILE} is writable.")  # Debug message
        except PermissionError:
            print(f"Error: Cannot write to {LOG_FILE}. Disabling logging.")
            ENABLE_LOGGING = False  # Thay đổi giá trị của biến toàn cục
        except FileNotFoundError:
            print(f"Error: Log file {LOG_FILE} not found. Please check the configuration.")
            ENABLE_LOGGING = False
        except Exception as e:
            print(f"Error accessing {LOG_FILE}: {e}. Disabling logging.")
            ENABLE_LOGGING = False  # Thay đổi giá trị của biến toàn cục

    # Load rules
    rules = load_rules()
    if not rules:
        print("No rules loaded. Exiting.")
        return

    # Start detection threads
    threads = [
        Thread(target=detect_portscan, args=(rules, port_scans, log_alert)),
        Thread(target=detect_dos, args=(rules, packet_counts, log_alert)),
        Thread(target=detect_ddos, args=(rules, packet_counts, log_alert)),
        Thread(target=detect_payload_attacks, args=(rules, packet_queue, log_alert)),
        Thread(target=detect_mitm, args=(rules, arp_table, log_alert)),
        Thread(target=detect_http_flood, args=(rules, http_requests, log_alert)),
        Thread(target=detect_ftp_bruteforce, args=(rules, login_attempts, log_alert)),
        Thread(target=detect_smtp_relay, args=(rules, packet_queue, log_alert)),
        Thread(target=detect_dns_amplification, args=(rules, dns_responses, log_alert)),
        Thread(target=detect_ssh_bruteforce, args=(rules, login_attempts, log_alert)),
        Thread(target=detect_telnet_bruteforce, args=(rules, login_attempts, log_alert)),
        Thread(target=detect_http_slowloris, args=(rules, http_requests, log_alert)),
        Thread(target=detect_icmp_ping_of_death, args=(rules, packet_queue, log_alert)),
        Thread(target=detect_ldap_injection, args=(rules, packet_queue, log_alert)),
        Thread(target=detect_snmp_bruteforce, args=(rules, login_attempts, log_alert)),
        Thread(target=detect_rdp_bruteforce, args=(rules, login_attempts, log_alert)),
    ]

    for thread in threads:
        thread.daemon = True
        thread.start()

    # Start sniffing
    sniff_thread = Thread(target=sniff_packets)
    sniff_thread.daemon = True
    sniff_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down IDS...")
        os._exit(0)

if __name__ == "__main__":
    main()
