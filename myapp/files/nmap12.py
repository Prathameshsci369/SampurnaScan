import socket
import threading
import logging
import random
import time
from scapy.all import ICMP, IP, TCP, sr1, sr
import requests

# Try importing Nmap
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Configure logging
log_file = "scan_results.log"
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", filename=log_file, filemode='a')

COMMON_PORTS = [80, 443, 21, 25, 110, 143, 3306, 23, 53, 8080, 8443, 161, 445, 3389, 6379, 995, 993, 465, 587, 22, 1521, 5432, 27017, 27018, 27019, 27020, 1433, 1434]
COMMON_PATHS = ["/robots.txt", "/admin", "/login", "/wp-login.php", "/phpinfo.php", "/.git/", "/config.php"]

class Scanner:
    def __init__(self, url, stealth=False):
        self.url = url
        self.stealth = stealth
        self.ip = self.get_ip_from_url(url)
        self.active_hosts = []
        self.os_detected = "Unknown OS"

    def log_and_print(self, message):
        """Logs to file and prints to console."""
        logging.info(message)
        print(message)

    def get_ip_from_url(self, url):  
        """Retrieve the IP address from the given URL and log the result."""
        try:
            ip = socket.gethostbyname(url.split("://")[-1])  # Strip protocol before resolving
            logging.info(f"URL: {url} -> IP Address: {ip}")
            return ip
        except socket.gaierror as e:
            self.log_and_print(f"Unable to resolve IP address for {url}: {e}")  # Log the error
            return None

    def ping_ip(self):
        """Ping the target to check reachability."""
        packet = IP(dst=self.ip) / ICMP()
        response = sr1(packet, timeout=1, verbose=0)
        return response is not None

    def detect_os(self):
        """Detect OS using ICMP TTL and TCP Window Size."""
        os_votes = {"Windows": 0, "Linux": 0, "Other": 0}

        # ICMP TTL Check
        icmp_response = sr1(IP(dst=self.ip) / ICMP(), timeout=1, verbose=0)
        if icmp_response:
            ttl = icmp_response.ttl
            if ttl >= 128:
                os_votes["Windows"] += 1
            elif ttl <= 64:
                os_votes["Linux"] += 1
            self.log_and_print(f"OS Detected via ICMP TTL: {ttl}")

        # TCP Window Size Check
        syn_packet = IP(dst=self.ip) / TCP(dport=80, flags="S")
        tcp_response = sr1(syn_packet, timeout=1, verbose=0)
        if tcp_response and tcp_response.haslayer(TCP):
            window_size = tcp_response.getlayer(TCP).window
            if window_size in [8192, 29200]:
                os_votes["Windows"] += 1
            elif window_size in [5840, 64240]:
                os_votes["Linux"] += 1
            else:
                os_votes["Other"] += 1
            self.log_and_print(f"OS Detected via TCP Window Size: {window_size}")

        self.os_detected = max(os_votes, key=os_votes.get)
        self.log_and_print(f"Final OS Detection Result: {self.os_detected}")

    def stealth_scan(self, port):
        """Perform a SYN scan on the specified port."""
        syn_packet = IP(dst=self.ip) / TCP(dport=port, flags="S")
        response = sr1(syn_packet, timeout=1, verbose=0)
        return response is not None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12

    def network_mapping(self):
        """Fix subnet scanning by properly iterating through all possible IPs."""
        subnet = ".".join(self.ip.split(".")[:3])
        for i in range(1, 255):  # Scanning range 1-254
            ip = f"{subnet}.{i}"
            packet = IP(dst=ip) / ICMP()
            response = sr1(packet, timeout=0.5, verbose=0)
            if response:
                if ip:  # Only append if the IP is valid
                    self.active_hosts.append(ip)
                    self.log_and_print(f"Active Host Found: {ip}")  # Log the found active host

    def web_vulnerability_scan(self):
        """Detect basic web vulnerabilities by checking common paths and headers."""
        self.log_and_print(f"Scanning web vulnerabilities on {self.ip}...")
        for path in COMMON_PATHS:
            url = f"http://{self.ip}{path}"
            try:
                response = requests.get(url, timeout=2)
                if response.status_code in [200, 403]:
                    self.log_and_print(f"⚠️ Possible Web Vulnerability: {path} ({response.status_code})")
            except requests.exceptions.RequestException:
                pass

    def banner_grabbing(self, port):
        """Retrieve service banners to detect versions."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((self.ip, port))
                sock.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8").strip()
                self.log_and_print(f"Banner for {self.ip}:{port} -> {banner}")
                return banner
        except:
            return None

    def detect_vulnerabilities(self, banner):
        """Check for known vulnerabilities in service banners."""
        for service, versions in {
            "FTP": ["vsFTPd 2.3.4"],  
            "SSH": ["OpenSSH 7.2p2"],  
            "HTTP": ["Apache 2.4.49"],  
            "MySQL": ["MySQL 5.7"],  
        }.items():
            for version in versions:
                if version in banner:
                    return f"Vulnerable: {service} - {version}"
        return "No known vulnerabilities detected."

    def scan_port(self, port):
        """Check if a port is open and grab banner if available."""
        if self.stealth:
            if self.stealth_scan(port):
                banner = self.banner_grabbing(port)
                if banner:
                    self.detect_vulnerabilities(banner)
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    if sock.connect_ex((self.ip, port)) == 0:
                        banner = self.banner_grabbing(port)
                        if banner:
                            self.detect_vulnerabilities(banner)
            except:
                pass

    def run_nmap_scan(self):
        if not NMAP_AVAILABLE:
            self.log_and_print("⚠️ Nmap library not found! Skipping Nmap scan.")
            return

        nm = nmap.PortScanner()
        self.log_and_print(f"Running Nmap Vulnerability Scan on {self.ip}...")
        nm.scan(self.ip, arguments="--script=vuln -sV")

        for host in nm.all_hosts():
            for port, details in nm[host]['tcp'].items():
                self.log_and_print(f"Nmap - Port {port}: {details['state']} {details.get('name', 'Unknown')}")
                if 'script' in details:
                    for script, output in details['script'].items():
                        self.log_and_print(f"Nmap Vulnerability Script {script}: {output}")

    def perform_scanning(self):  
        """Perform the complete scanning process and return structured results."""
        if not self.ip or not self.ping_ip():
            logging.error("IP is not reachable or not set.")
            return
        self.log_and_print(f"Scanning target: {self.url} ({self.ip})")
        self.network_mapping()
        self.detect_os()
        self.web_vulnerability_scan()

        threads = [threading.Thread(target=self.scan_port, args=(port,)) for port in COMMON_PORTS]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.log_and_print("Custom script scan completed. Running Nmap next...\n")
        time.sleep(2)  
        self.run_nmap_scan()
        return {
            "ip": self.ip,
            "activehosts": self.active_hosts,
            "osdetected": self.os_detected,
        }

    def scan_url(url, stealth=False):
        scanner = Scanner(url, stealth)
        scanner.perform_scanning()
        return {
            "ip": scanner.ip,
            "active_hosts": scanner.active_hosts,
            "os_detected": scanner.os_detected,
            "log_file": log_file,
            "nmap_results": scanner.run_nmap_scan() if NMAP_AVAILABLE else "Nmap not available"
        }
        

# Run both scanners in one file
# url = "mmec.edu.in"
# scanner = Scanner(url,stealth=False)
# print(scanner.perform_scanning())
