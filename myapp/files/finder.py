import re  # रेग्युलर एक्सप्रेशन्ससाठी
import requests  # HTTP विनंत्या करण्यासाठी
import time  # वेळ संबंधित कार्यांसाठी
from urllib.parse import urljoin  # URL जॉइन करण्यासाठी
from playwright.sync_api import sync_playwright  # Playwright वापरून ब्राउझर ऑटोमेशनसाठी

from .api_validations import validate_key  # Updated import statement

class Finder:
    def __init__(self, url):
        self.url = url  # URL सेट करणे
        self.js_files = []  # JavaScript फाइल्सची यादी
        self.results = {
            'validmatches': {"valid_matches": [], "unvalidated_matches": []},  # वैध जुळणी
            'unvalidatedmatches': {"valid_matches": [], "unvalidated_matches": []},  # अवैध जुळणी
        }
        
        self.regex_patterns = {  # रेग्युलर एक्सप्रेशन्स पॅटर्न्स
            'google_api': r'AIza[0-9A-Za-z-_]{35}',
            'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
            'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
            'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
            'amazon_mws_auth_token': (
                r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-'
                r'[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
            ),
            'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
            'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
            'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
            'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
            'twilio_api_key': r'SK[0-9a-fA-F]{32}',
            'twilio_account_sid': r'AC[a-zA-Z0-9]{60}',
            'twilio_app_sid': r'AP[a-zA-Z0-9]{60}',
            'paypal_braintree_access_token': (
                r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'
            ),
            'square_oauth_secret': (
                r'sq0csp-[0-9a-zA-Z]{32}|sq0[a-z]{3}-[0-9a-zA-Z]{22,43}'
            ),
            'square_access_token': r'sqOatp-[0-9a-zA-Z]{22}|EAAA[a-zA-Z0-9]{60}',
            'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
            'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
            'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
            'rsa_private_key': (
                r'-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----'
            ),
            'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
            'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
            'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            'slack_token': r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"',
            'SSH_privKey': (
                r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)"
            ),
            'Heroku_API_KEY': (
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-'
                r'[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
            ),
            'possible_Creds': r"(?i)(password\s*[`=:\"]+\s*[^\s]+)",
            'password': r'password\s*[`=:\"]+\s*[^\s]+'
        }

    def get_js_files(self):
        try:
            with sync_playwright() as p:  # Playwright वापरून ब्राउझर ऑटोमेशन
                browser = p.chromium.launch(headless=True)  # हेडलेस ब्राउझर लाँच करणे
                page = browser.new_page()  # नवीन पेज तयार करणे
                page.goto(self.url)  # URL ला भेट देणे
                page.wait_for_load_state("load")  # पेज लोड होण्याची वाट पाहणे

                js_files = []  # JavaScript फाइल्सची यादी
                scripts = page.query_selector_all("script[src]")  # सर्व <script> टॅग शोधणे
                for script in scripts:
                    script_url = script.get_attribute("src")  # script URL मिळवणे
                    if script_url:
                        full_url = urljoin(self.url, script_url)  # पूर्ण URL तयार करणे
                        js_files.append(full_url)  # यादीत URL जोडणे

                browser.close()  # ब्राउझर बंद करणे
            print(f"\n✅ Extracted JavaScript Files: {js_files}\n")  # Debugging output
            return js_files  # JavaScript फाइल्स परत करणे
        except Exception as e:
            print(f"\n❌ Error extracting JavaScript files: {e}\n")  # एरर संदेश
            return []  # रिकामी यादी परत करणे

    def find_sensitive_info(self, js_content, js_file):
        for key, pattern in self.regex_patterns.items():  # प्रत्येक रेग्युलर एक्सप्रेशन पॅटर्नसाठी
            matches = re.findall(pattern, js_content)  # जुळणारे पॅटर्न शोधणे
            if matches:
                if key not in self.results:
                    self.results[key] = {"valid_matches": [], "unvalidated_matches": []}  # निकाल संरचना

                for match in matches:
                    print(f"\n🔍 Found match for {key}: {match} in {js_file}\n")  # Debugging output
                    if validate_key(key, match):  # की वैध आहे का तपासणे
                        self.results[key]["valid_matches"].append((match, js_file))  # वैध जुळणी जोडणे
                    else:
                        self.results[key]["unvalidated_matches"].append((match, js_file))  # अवैध जुळणी जोडणे

    def run(self):
        self.js_files = self.get_js_files()  # JavaScript फाइल्स मिळवणे
        if not self.js_files:
            print("\n❌ No JavaScript files found.\n")  # एरर संदेश
            return

        for js_file in self.js_files:  # प्रत्येक JavaScript फाइलसाठी
            try:
                response = requests.get(js_file)  # फाइलला विनंती करणे
                response.raise_for_status()  # स्टेटस तपासणे
                print(f"\n✅ Fetched JS File: {js_file}\n")  # Debugging output
                print(f"🔹 JS Content: {response.text[:500]}...\n")  # Print first 500 characters
                self.find_sensitive_info(response.text, js_file)  # संवेदनशील माहिती शोधणे
            except requests.RequestException as e:
                print(f"\n❌ Error fetching {js_file}: {e}\n")  # एरर संदेश

    def get_results(self):
        print(f"\n🔍 Final Finder Results: {self.results}\n")  # Debugging output
        return self.results  # निकाल परत करणे

if __name__ == "__main__":
    url = input("Enter the URL of the website to scan: ")  # स्कॅन करण्यासाठी वेबसाइट URL प्रविष्ट करा
    finder = Finder(url)  # Finder ऑब्जेक्ट तयार करणे
    finder.run()  # Finder चालवणे



"""
हा फाइल Django प्रोजेक्टमध्ये वेबसाइटवरील संवेदनशील माहिती शोधण्यासाठी वापरला जातो. 
या फाइलमध्ये `Finder` क्लास आहे जो JavaScript फाइल्समधून संवेदनशील माहिती शोधतो. 
`get_js_files` फंक्शन Playwright वापरून वेबसाइटवरील सर्व JavaScript फाइल्स शोधतो. 
`find_sensitive_info` फंक्शन रेग्युलर एक्सप्रेशन्स वापरून JavaScript फाइल्समधील संवेदनशील माहिती शोधतो. 
`run` फंक्शन सर्व JavaScript फाइल्स मिळवून त्यांचे विश्लेषण करते. 
`get_results` फंक्शन अंतिम निकाल परत करते. 
या फाइलचा वापर करून, वेबसाइटवरील संवेदनशील माहिती शोधता येते आणि तिचे विश्लेषण करता येते. 
भविष्यातील फिचर्ससाठी नवीन रेग्युलर एक्सप्रेशन्स आणि विश्लेषण जोडता येते. 
या फाइलमध्ये विविध रेग्युलर एक्सप्रेशन्स पॅटर्न्स आहेत जे विविध प्रकारच्या संवेदनशील माहिती शोधण्यासाठी वापरले जातात. 
या फाइलचा वापर करून, वेबसाइटवरील संवेदनशील माहिती शोधणे आणि तिचे विश्लेषण करणे सोपे होते.
"""