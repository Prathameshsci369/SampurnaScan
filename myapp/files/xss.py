import logging
from playwright.sync_api import sync_playwright

class VulnerabilityScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)

    def is_fillable_element(self, element):
        """Check if an element can be filled with text"""
        try:
            tag_name = element.get_attribute("tagName")
            input_type = element.get_attribute("type")
            
            # Handle None values
            tag_name = tag_name.lower() if tag_name else ''
            input_type = input_type.lower() if input_type else ''
            
            # Elements that can be filled
            fillable_tags = ['input', 'textarea']
            
            # Input types that cannot be filled
            non_fillable_types = ['submit', 'button', 'image', 'reset']
            
            return (tag_name in fillable_tags and 
                    input_type not in non_fillable_types)
        except Exception as e:
            self.logger.error(f"Error checking element: {e}")
            return False

    def scan_xss(self, url, payloads):
        """Scan for XSS vulnerabilities"""
        results = []
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=False)
            page = browser.new_page()
            page.goto(url)

            # Wait for page to load completely
            page.wait_for_load_state("networkidle")

            # Get all potential input elements
            elements = page.query_selector_all("input, textarea, select, button")
            self.logger.info(f"Found {len(elements)} elements.")

            for index, element in enumerate(elements):
                self.logger.info(f"Testing element {index + 1}/{len(elements)}")
                
                # Create new page for each element to maintain state
                element_page = browser.new_page()
                element_page.goto(url)
                element_page.wait_for_load_state("networkidle")
                
                # Get the element on the new page
                current_element = element_page.query_selector_all("input, textarea, select, button")[index]
                
                # Skip non-fillable elements
                if not self.is_fillable_element(current_element):
                    self.logger.info(f"Skipping non-fillable element {index + 1}")
                    element_page.close()
                    continue
                
                for payload in payloads:
                    try:
                        # Ensure element is visible and enabled
                        if not current_element.is_visible() or not current_element.is_enabled():
                            continue

                        # Clear and fill the element with payload as-is
                        current_element.fill("")
                        current_element.fill(payload)
                        
                        # Check for XSS vulnerability
                        result = element_page.evaluate(f"""
                            (function() {{
                                var payload = `{payload}`;
                                document.body.innerHTML += payload;
                                return document.body.innerHTML.includes(payload);
                            }})()
                        """)

                        if result:
                            self.logger.info(f"XSS vulnerability found! Payload: {payload}")
                            results.append({
                                "element": index + 1,
                                "payload": payload,
                                "status": "Vulnerable",
                                "url": url
                            })

                        # Submit form if available
                        form = current_element.query_selector("xpath=ancestor::form")
                        if form:
                            form.evaluate("form => form.submit()")
                            element_page.wait_for_load_state("networkidle")

                    except Exception as e:
                        self.logger.error(f"Error testing payload {payload}: {e}")
                
                # Close the element page after testing all payloads
                element_page.close()

            browser.close()
        return results

def read_xss_payloads(filename):
    """Read XSS payloads from file"""
    try:
        with open(filename, "r") as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        logging.error("Payload file not found.")
        return []
