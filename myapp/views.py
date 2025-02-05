import os  # OS संबंधित कार्यांसाठी
import logging  # लॉगिंगसाठी
from django.shortcuts import render  # रेंडरिंगसाठी
from .forms import TaskForm  # TaskForm इम्पोर्ट करणे
from .files.xss import VulnerabilityScanner, read_xss_payloads  # XSS संबंधित कार्यांसाठी
from .files.app import WebsiteInfoGatherer  # वेबसाइट माहिती गोळा करण्यासाठी
from .files.finder import Finder   # Finder इम्पोर्ट करणे
from django.http import HttpResponse
 
class VulnerabilityView:
    def __init__(self):
        self.logger = logging.getLogger(__name__)  # लॉगर सेट करणे
        self.payload_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'myapp',
            'files',
            'xsspayload.txt'
        )  # पेलोड फाइलचा पथ सेट करणे
        self.logger.debug(f"Payload file path: {self.payload_path}")
        
        if not os.path.exists(self.payload_path):  # जर payload_path अस्तित्वात नसेल तर
            self.logger.error(f"Payload file not found at: {self.payload_path}")
            raise FileNotFoundError(f"Payload file not found at: {self.payload_path}")

    def home(self, request):
        self.logger.debug("Home view accessed.")  # Debugging statement
        context = {}  # संदर्भ सेट करणे

        if request.method == "POST":  # Handle POST request
            url = request.POST.get("url")  # POST विनंतीतून URL मिळवणे
            self.logger.debug(f"Received URL: {url}")  # Debugging statement

            if url:  # जर URL POST विनंतीतून प्राप्त झाला असेल तर
                finder = Finder(url)  # Finder ऑब्जेक्ट तयार करणे
                finder.run()  # Finder चालवणे
                finder_results = finder.get_results()  # Finder चे निकाल मिळवणे

                self.logger.debug(f"Finder Results: {finder_results}")  # Debugging output

                context["finder_results"] = {
                    "validmatches": finder_results.get("validmatches", {}).get("valid_matches", []),  # वैध जुळणी
                    "unvalidatedmatches": finder_results.get("unvalidatedmatches", {}).get("unvalidated_matches", []),  # अवैध जुळणी
                    "authorization_api": finder_results.get("authorization_api", {}).get("unvalidated_matches", []),  # अधिकृतता API
                    "possible_Creds": finder_results.get("possible_Creds", {}).get("unvalidated_matches", []),  # संभाव्य क्रेडेन्शियल्स
                    "database_Creds": finder_results.get("database_Creds", {}).get("unvalidated_matches", []),  # डेटाबेस क्रेडेन्शियल्स
                    "jwt_Tokens": finder_results.get("jwt_Tokens", {}).get("unvalidated_matches", []),  # JWT टोकन्स
                    "hardcoded_Passwords": finder_results.get("hardcoded_Passwords", {}).get("unvalidated_matches", [])  # हार्डकोडेड पासवर्ड्स
                }

                # WebsiteInfoGatherer कॉल करणे
                gatherer = WebsiteInfoGatherer(url)  # WebsiteInfoGatherer ऑब्जेक्ट तयार करणे
                info = gatherer.gather_all_info()  # सर्व माहिती गोळा करणे

                # प्रदर्शनासाठी निकाल संरचना
                context["results"] = {
                    "Metadata": info.get("Metadata", {}),
                    "Domain": info.get("Domain", "No domain info available."),
                    "IP": info.get("IP", "No IP address found."),
                    "Technology": info.get("Technology", "No technology stack found."),
                    "SSL": info.get("SSL", "No SSL certificate found."),
                    "Performance": info.get("Performance", "No performance metrics found."),
                    "Content": info.get("Content", "No content analysis found."),
                    "Security": info.get("Security", "No security features found."),
                    "Geo": info.get("Geo", "No geolocation found."),
                    "Robots": info.get("Robots", "No robots.txt found."),
                    "Sitemap": info.get("Sitemap", "No sitemap.xml found."),
                    "Social": info.get("Social", "No social media links found."),
                    "Backlinks": info.get("Backlinks", "No backlinks or authority found."),
                    "WordPress": info.get("WordPress", "No WordPress detected.")
                }
                context["url"] = url  # संदर्भात URL सेट करणे
        else:  # Handle GET request
            self.logger.debug("GET request received for home view.")
        
        return render(request, "home.html", context)  # होम टेम्पलेट रेंडर करणे

try:
    vulnerability_view = VulnerabilityView()  # VulnerabilityView ऑब्जेक्ट तयार करणे
    home = vulnerability_view.home  # होम फंक्शन सेट करणे
except FileNotFoundError as e:
    logging.error(f"Failed to initialize VulnerabilityView: {e}")  # लॉगिंग एरर
