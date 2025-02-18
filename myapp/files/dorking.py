import requests
import logging
import random
import time
from playwright.sync_api import sync_playwright
from .dorks import Dorks

class DorkingTool:
    def __init__(self):
        """Initialize the DorkingTool with logging and dork mappings"""
        self.logger = logging.getLogger(__name__)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        self.dork_mapping = {
            "info": "get_info_dorks",
            "files": "get_exposed_files_dorks",
            "vuln": "get_vulnerability_dorks",
            "camera": "get_camera_iot_dorks",
            "cloud": "get_cloud_storage_dorks",
            "code": "get_code_docs_dorks",
            "subdomains": "get_subdomain_dorks",
            "open_dirs": "get_open_directories_dorks",
            "sensitive": "get_sensitive_files_dorks",
            "sql_errors": "get_sql_error_dorks",
            "routers": "get_private_routers_dorks",
            "login": "get_login_pages_dorks",
            "errorp": "get_error_pages_dorks",
            "backup": "get_backup_files_dorks",
            "all": "get_all_dorks"
        }

    def google_dork(self, domain, dork_type="info"):
        """Perform Google dorking using Playwright with parallel tab execution"""
        self.logger.info(f"Starting dorking for domain: {domain} with type: {dork_type}")
        
        if dork_type not in self.dork_mapping:
            error_msg = f"Invalid dork type. Choose from: {', '.join(self.dork_mapping.keys())}"
            self.logger.error(error_msg)
            raise ValueError(error_msg)

        dorks_instance = Dorks(domain)
        dork_method = getattr(dorks_instance, self.dork_mapping[dork_type])
        dorks = dork_method()
        self.logger.info(f"Generated {len(dorks)} dorks for search")
    
        results = []
        with sync_playwright() as p:
            self.logger.info("Initializing Playwright browser")
            try:
                browser = p.chromium.launch(
                    headless=False,  # Make browser visible for debugging
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--no-sandbox',
                        '--disable-setuid-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-software-rasterizer',
                        '--disable-extensions',
                        '--window-size=1920,1080',
                        '--start-maximized'
                    ],
                    slow_mo=100  # Add delay between actions
                )
                context = browser.new_context(
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    viewport={'width': 1366, 'height': 768}
                )
                self.logger.info("Browser context created successfully")
        
            except Exception as e:
                self.logger.error(f"Failed to initialize browser: {str(e)}")
                raise

            # Process dorks in parallel using multiple tabs
            max_tabs = 5
            active_tabs = []
            
            for i, dork in enumerate(dorks):
                if len(active_tabs) >= max_tabs:
                    # Wait for the first tab to complete
                    page = active_tabs.pop(0)
                    try:
                        # Try multiple selectors with increased timeout
                        try:
                            page.wait_for_selector('div.g', timeout=6000)
                        except:
                            try:
                                page.wait_for_selector('div#search', timeout=50000)
                            except:
                                page.wait_for_selector('div#rso', timeout=5000)
                    except Exception as e:
                        self.logger.warning(f"Error waiting for results: {str(e)}")
                        page.close()
                        continue
                    
                    # Extract results from completed tab
                    try:
                        links = page.query_selector_all('div.g a')
                        self.logger.info(f"Found {len(links)} potential results")
                        for link in links[:8]:
                            try:
                                href = link.get_attribute('href')
                                if href and href.startswith('http'):
                                    try:
                                        response = requests.get(href, timeout=10)
                                        if response.status_code == 200:
                                            results.append(href)
                                            self.logger.debug(f"Valid URL found: {href}")
                                    except Exception as e:
                                        self.logger.warning(f"Error validating URL {href}: {str(e)}")
                                        continue
                            except Exception as e:
                                self.logger.warning(f"Error extracting link: {str(e)}")
                                continue
                    except Exception as e:
                        self.logger.error(f"Error finding search results: {str(e)}")
                    
                    page.close()
                
                # Create new tab for current dork
                try:
                    self.logger.info(f"Processing dork {i+1}/{len(dorks)}: {dork}")
                    new_page = context.new_page()
                    
                    # Add retry logic for Google search
                    max_retries = 3
                    for attempt in range(max_retries):
                        try:
                            new_page.goto("https://www.google.com", timeout=120000)
                            new_page.wait_for_selector('textarea[name="q"]', timeout=60000)
                            break
                        except Exception as e:
                            if attempt == max_retries - 1:
                                raise
                            self.logger.warning(f"Retry {attempt + 1} for Google search")
                            time.sleep(5)
                    
                    for char in dork:
                        new_page.keyboard.type(char)
                        time.sleep(random.uniform(0.05, 0.2))
                    
                    new_page.keyboard.press("Enter")
                    
                    # Wait for results with multiple selector options
                    try:
                        try:
                            new_page.wait_for_selector('div.g', timeout=120000)
                        except:
                            try:
                                new_page.wait_for_selector('div#search', timeout=120000)
                            except:
                                new_page.wait_for_selector('div#rso', timeout=120000)
                        
                        # Check for "did not match any documents" message
                        if new_page.query_selector("div#topstuff"):
                            no_results_text = new_page.query_selector("div#topstuff").inner_text()
                            if "did not match any documents" in no_results_text:
                                self.logger.info(f"No results found for dork: {dork}")
                                new_page.close()
                                continue
                        
                        active_tabs.append(new_page)
                    except Exception as e:
                        self.logger.warning(f"Timeout waiting for results: {str(e)}")
                        new_page.close()
                        continue

                except Exception as e:
                    self.logger.error(f"Error processing dork {dork}: {str(e)}")
                    if 'new_page' in locals():
                        new_page.close()

            # Process remaining tabs
            while active_tabs:
                page = active_tabs.pop(0)
                try:
                    try:
                        page.wait_for_selector('div.g', timeout=120000)
                    except:
                        try:
                            page.wait_for_selector('div#search', timeout=120000)
                        except:
                            page.wait_for_selector('div#rso', timeout=120000)
                except Exception as e:
                    self.logger.warning(f"Timeout waiting for results: {str(e)}")
                    page.close()
                    continue
                
                try:
                    links = page.query_selector_all('div.g a')
                    self.logger.info(f"Found {len(links)} potential results")
                    for link in links[:8]:
                        try:
                            href = link.get_attribute('href')
                            if href and href.startswith('http'):
                                try:
                                    response = requests.get(href, timeout=10)
                                    if response.status_code == 200:
                                        results.append(href)
                                        self.logger.debug(f"Valid URL found: {href}")
                                except Exception as e:
                                    self.logger.warning(f"Error validating URL {href}: {str(e)}")
                                    continue
                        except Exception as e:
                            self.logger.warning(f"Error extracting link: {str(e)}")
                            continue
                except Exception as e:
                    self.logger.error(f"Error finding search results: {str(e)}")
                
                page.close()

            try:
                context.close()
                browser.close()
                self.logger.info("Browser context closed successfully")
            except Exception as e:
                self.logger.error(f"Error closing browser: {str(e)}")
        
        return list(set(results))

# Main function
if __name__ == "__main__":
    dork_tool = DorkingTool()
    target_domain = input("Enter the domain to perform dorking on: ")
    print(f"Available dork types: {', '.join(dork_tool.dork_mapping.keys())}")
    dork_type = input("Enter the dork type: ")
    
    try:
        results = dork_tool.google_dork(target_domain, dork_type)
        print("\nClean Dorking Results:")
        for result in results:
            print(f"- {result}")
    except ValueError as e:
        print(f"Error: {e}")