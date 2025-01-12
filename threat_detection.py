from scapy.all import sniff, IP, TCP
import json
import os
from datetime import datetime

# Configuration
LOG_DIR = './logs'
REPORT_DIR = './reports'
RULES_FILE = 'rules.json'
LOG_FILE = f'{LOG_DIR}/threats.log'

# Ensure directories exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

def load_rules():
    """Load detection rules from JSON file."""
    with open(RULES_FILE, 'r') as file:
        return json.load(file)

def log_threat(packet, reason):
    """Log suspicious packets."""
    with open(LOG_FILE, 'a') as log:
        log.write(f"[{datetime.now()}] Suspicious packet detected: {packet.summary()} - Reason: {reason}\n")

def generate_report():
    """Generate daily threat report."""
    report_file = f"{REPORT_DIR}/report_{datetime.now().strftime('%Y%m%d')}.txt"
    with open(LOG_FILE, 'r') as log:
        log_data = log.read()
    
    with open(report_file, 'w') as report:
        report.write(f"Daily Threat Report - {datetime.now().strftime('%Y-%m-%d')}\n")
        report.write("=" * 40 + "\n\n")
        report.write(log_data)

def detect_threat(packet, rules):
    """Check packet against detection rules."""
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        for rule in rules:
            if rule["type"] == "port" and dst_port == rule["value"]:
                log_threat(packet, f"Port {dst_port} matches rule")
            elif rule["type"] == "ip" and src_ip == rule["value"]:
                log_threat(packet, f"Source IP {src_ip} matches rule")

def packet_handler(packet):
    """Process incoming packets."""
    rules = load_rules()
    detect_threat(packet, rules)

if __name__ == "__main__":
    print("Starting network threat detection system...")
    sniff(filter="ip", prn=packet_handler, store=0)
    generate_report()
