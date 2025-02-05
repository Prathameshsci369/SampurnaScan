import requests  # HTTP विनंत्या करण्यासाठी
import socket  # नेटवर्क संबंधित कार्यांसाठी
import ssl  # SSL प्रमाणपत्रांसाठी
import whois  # डोमेन माहिती मिळवण्यासाठी
from bs4 import BeautifulSoup  # HTML पार्सिंगसाठी
import json  # JSON डेटा हाताळण्यासाठी
from urllib.parse import urlparse  # URL पार्सिंगसाठी
import re  # रेग्युलर एक्सप्रेशन्ससाठी
import logging  # लॉगिंगसाठी
from .tech_detector import TechDetector  # तंत्रज्ञान शोधण्यासाठी

class Utility:
    @staticmethod
    def validate_url(url):
        regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// किंवा https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # डोमेन...
            r'localhost|'  # लोकलहोस्ट...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
            r'(?::\d+)?'  # वैकल्पिक पोर्ट
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return re.match(regex, url) is not None  # URL वैध आहे का तपासणे

class WebsiteInfoGatherer:
    def __init__(self, url):
        self.url = url if url.startswith("http") else f"http://{url}"  # URL सेट करणे
        self.parsed_url = urlparse(self.url)  # URL पार्स करणे
        self.domain = urlparse(url).netloc  # डोमेन मिळवणे
        self.hostname = urlparse(self.url).hostname  # होस्टनेम मिळवणे
        DEFAULT_TIMEOUT = 10  # डीफॉल्ट टाइमआउट सेट करणे
        response = requests.get(self.url, timeout=DEFAULT_TIMEOUT)  # URL ला विनंती करणे

    def fetch_ip_address(self):
        """Fetch the IP address of the hostname."""
        try:
            ip_address = socket.gethostbyname(self.hostname)  # होस्टनेमचा IP पत्ता मिळवणे
            return ip_address
        except socket.gaierror as e:
            logging.error(f"Could not fetch IP address: {e}")  # IP पत्ता मिळवण्यात अयशस्वी
            return None

    def fetch_metadata(self):
        """मूलभूत मेटाडेटा मिळवा: शीर्षक, वर्णन, कीवर्ड."""  # Translated comment
        try:
            response = requests.get(self.url)  # URL ला विनंती करणे
            response.raise_for_status()  # स्टेटस तपासणे
            soup = BeautifulSoup(response.text, 'html.parser')  # HTML पार्स करणे
            metadata = {
                'Title': soup.title.string if soup.title else 'No title',  # शीर्षक मिळवणे
                'Description': soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else 'No description',  # वर्णन मिळवणे
                'Keywords': soup.find('meta', {'name': 'keywords'})['content'] if soup.find('meta', {'name': 'keywords'}) else 'No keywords'  # कीवर्ड्स मिळवणे
            }
            return metadata  # मेटाडेटा परत करणे
        except requests.exceptions.RequestException as e:
            return {"Error": f"Failed to fetch metadata: {e}"}  # एरर परत करणे

    def get_ssl_certificate(self):
        try:
            hostname = self.parsed_url.hostname  # होस्टनेम मिळवणे
            context = ssl.create_default_context()  # SSL कॉन्टेक्स्ट तयार करणे
            with socket.create_connection((hostname, 443), timeout=10) as sock:  # कनेक्शन तयार करणे
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:  # SSL कनेक्शन तयार करणे
                    cert = ssock.getpeercert()  # प्रमाणपत्र मिळवणे
            return {
                "Common Name (CN)": cert.get("subject", [[("commonName", "")]])[0][0][1],  # सामान्य नाव
                "Issuer": cert.get("issuer", [[("commonName", "")]])[0][0][1],  # जारीकर्ता
                "Valid From": cert.get("notBefore"),  # वैधता प्रारंभ
                "Valid To": cert.get("notAfter"),  # वैधता समाप्त
                "Subject Alternative Names (SANs)": cert.get("subjectAltName", []),  # पर्यायी नावे
            }
        except (ssl.SSLError, socket.error) as e:
            return {"Error": f"SSL प्रमाणपत्र मिळवण्यात अयशस्वी: {e}"}  # Translated error message

    def get_geolocation(self, ip_address):
        try:
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")  # IP माहिती मिळवणे
            if response.status_code == 200:
                data = response.json()  # JSON डेटा पार्स करणे
                return {
                    "IP": data.get("ip"),  # IP पत्ता
                    "Country": data.get("country"),  # देश
                    "Region": data.get("region"),  # प्रदेश
                    "City": data.get("city"),  # शहर
                    "Coordinates": data.get("loc"),  # समन्वय
                }
            else:
                return {"Error": f"Geolocation मिळवण्यात अयशस्वी (Status: {response.status_code})"}  # एरर परत करणे
        except Exception as e:
            return {"Error": str(e)}  # एरर परत करणे

    def get_domain_info(self):
        return f"Domain: {self.domain}, Hostname: {self.hostname}"  # डोमेन आणि होस्टनेम परत करणे
    
    def get_technology_stack(self):
        try:
            response = requests.get(self.url)  # URL ला विनंती करणे
            html_content = response.text  # HTML सामग्री मिळवणे
            headers = response.headers  # हेडर्स मिळवणे
            detector = TechDetector()  # Initialize TechDetector
            technologies = detector.detect_technologies(html_content, headers)  # तंत्रज्ञान शोधणे
            return technologies if technologies else "Unknown"  # तंत्रज्ञान परत करणे
        except Exception as e:
            logging.error(f"तंत्रज्ञान स्टॅक मिळवण्यात अयशस्वी: {e}")  # Translated error message
            return "Unknown"  # एरर परत करणे

    def gather_all_info(self):
        ip = self.fetch_ip_address()  # IP पत्ता मिळवणे
        return {
            "SSL": self.get_ssl_certificate(),  # SSL प्रमाणपत्र
            "IP": ip,  # IP पत्ता
            "Metadata": self.fetch_metadata(),  # मेटाडेटा
            "Technology": self.get_technology_stack(),  # तंत्रज्ञान स्टॅक
        }

# Main script
if __name__ == "__main__":
    website_url = input("Enter the website URL: ")  # वेबसाइट URL प्रविष्ट करा
    if not Utility.validate_url(website_url):  # URL वैध आहे का तपासणे
        print("Invalid URL. Please enter a valid website URL (e.g., https://example.com).")  # अवैध URL संदेश
    else:
        gatherer = WebsiteInfoGatherer(website_url)  # WebsiteInfoGatherer ऑब्जेक्ट तयार करणे
        info = gatherer.gather_all_info()  # सर्व माहिती गोळा करणे
        
        # निकाल लेबल केलेल्या स्वरूपात प्रिंट करा
        for section, details in info.items():  # प्रत्येक विभागासाठी
            print(f"\n=== {section} ===")  # विभाग शीर्षक प्रिंट करणे
            if isinstance(details, dict):  # जर तपशील डिक्शनरी असेल तर
                for key, value in details.items():  # प्रत्येक की-वॅल्यू जोडासाठी
                    print(f"{key}: {value}")  # की-वॅल्यू प्रिंट करणे
            else:
                print(details)  # तपशील प्रिंट करणे
