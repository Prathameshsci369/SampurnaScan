import re  # नियमित अभिव्यक्तींसाठी (For regular expressions)
import json  # JSON डेटा हाताळण्यासाठी (For handling JSON data)
import logging  # लॉगिंगसाठी (For logging)
import requests  # HTTP विनंत्या करण्यासाठी (For making HTTP requests)
from bs4 import BeautifulSoup  # HTML पार्सिंगसाठी (For parsing HTML)
import os  # ऑपरेटिंग सिस्टम संबंधित कार्यांसाठी (For operating system related tasks)

class TechDetector:
    def __init__(self, config_file=None):
        self.default_patterns = self.get_default_patterns()  # डीफॉल्ट पॅटर्न्स मिळवा (Get default patterns)
        self.user_patterns = self.load_custom_patterns(config_file) if config_file else {}  # वापरकर्ता पॅटर्न्स लोड करा (Load user patterns if config file is provided)
        # डीबगिंग: फक्त वापरकर्ता पॅटर्न्स अस्तित्वात असताना प्रिंट करा (Debugging: Print only when user patterns exist)
        if self.user_patterns:
            logging.info(f"User-defined patterns loaded: {self.user_patterns}")

    def get_default_patterns(self):
        return {
            "html_patterns": {
                'jQuery': r'jquery',
                'Bootstrap': r'bootstrap',
                'AngularJS': r'ng-app',
                'React': r'react',
                'Vue.js': r'vue',
                'Ruby on Rails': r'rails',
                'Laravel': r'laravel',
                'Django': r'csrfmiddlewaretoken',
                'Flask': r'flask',
                'Spring': r'spring',
                'ASP.NET': r'asp.net',
                'Express': r'express',
                'PHP': r'php',
                'Node.js': r'node.js',
                'Java': r'java',
                'Python': r'python',
                'Nginx': r'nginx',
                'Apache': r'apache',
                'Microsoft-IIS': r'microsoft-iis',
                'Cloudflare': r'cloudflare',
                'Amazon Web Services': r'amazon',
                'Google Cloud Platform': r'gcp|google',
                'Heroku': r'heroku',
                'DigitalOcean': r'digitalocean',
                'Vercel': r'vercel',
                'Netlify': r'netlify',
                'Magento': r'magento',
                'Shopify': r'shopify',
                'WooCommerce': r'woocommerce',
                'Squarespace': r'squarespace',
                'Wix': r'wix',
                'BigCommerce': r'bigcommerce',
                'PrestaShop': r'prestashop',
                'OpenCart': r'opencart',
                'Joomla': r'joomla',
                'Drupal': r'drupal',
                'Ghost': r'ghost',
                'Hugo': r'hugo',
                'Jekyll': r'jekyll',
                'Grav': r'grav',
                'Gatsby': r'gatsby',
                'Next.js': r'next.js',
                'Nuxt.js': r'nuxt.js',
                'Svelte': r'svelte',
                'Meteor': r'meteor',
                'Ember.js': r'ember.js',
                'Backbone.js': r'backbone.js',
                'Knockout.js': r'knockout.js',
                'Polymer': r'polymer',
                'Alpine.js': r'alpine.js',
                'Tailwind CSS': r'tailwindcss',
                'Bulma': r'bulma',
                'Foundation': r'foundation',
                'Materialize': r'materialize',
                'Semantic UI': r'semantic-ui',
                'UIKit': r'uikit',
                'Ant Design': r'ant-design',
                'Element UI': r'element-ui',
                'Vuetify': r'vuetify',
                'PrimeNG': r'primeng',
                'PrimeReact': r'primereact',
                'PrimeVue': r'primevue',
                'Kendo UI': r'kendo-ui',
                'Syncfusion': r'syncfusion',
                'DevExpress': r'devexpress',
                'Telerik': r'telerik',
                'Infragistics': r'infragistics',
                'Highcharts': r'highcharts',
                'Chart.js': r'chart.js',
                'D3.js': r'd3.js',
                'Three.js': r'three.js',
                'Leaflet': r'leaflet',
                'Mapbox': r'mapbox',
                'OpenLayers': r'openlayers',
                'Cesium': r'cesium',
                'Plotly': r'plotly',
                'ECharts': r'echarts',
                'ApexCharts': r'apexcharts',
                'FusionCharts': r'fusioncharts',
                'Google Charts': r'google-charts',
                'Chartist': r'chartist',
                'C3.js': r'c3.js',
                'NVD3': r'nvd3',
                'Vis.js': r'vis.js',
                'Sigma.js': r'sigma.js',
                'Cytoscape.js': r'cytoscape.js',
                'JointJS': r'jointjs',
                'GoJS': r'gojs',
                'Mermaid': r'mermaid',
                'PlantUML': r'plantuml',
                'Graphviz': r'graphviz',
                'Dagre': r'dagre',
                'Springy': r'springy',
                'Arbor.js': r'arbor.js',
                'Vega': r'vega',
                'Vega-Lite': r'vega-lite',
                'Deck.gl': r'deck.gl',
                'Kepler.gl': r'kepler.gl',
                'Luma.gl': r'luma.gl',
                'H3.js': r'h3.js',
                'WordPress': r'wp-content|wp-includes|<meta name=["\']generator["\'] content=["\']WordPress'
            },
            "header_patterns": {
                'ASP.NET': r'asp.net',
                'Flask': r'flask',
                'Spring': r'spring',
                'Express': r'express',
                'PHP': r'php',
                'Node.js': r'node.js',
                'Java': r'java',
                'Python': r'python',
                'Nginx': r'nginx',
                'Apache': r'apache',
                'Microsoft-IIS': r'microsoft-iis',
                'Cloudflare': r'cloudflare',
                'Amazon Web Services': r'amazon',
                'Google Cloud Platform': r'gcp|google',
                'Heroku': r'heroku',
                'DigitalOcean': r'digitalocean',
                'Vercel': r'vercel',
                'Netlify': r'netlify',
                'WordPress': r'wordpress'
            }
        }

    def load_custom_patterns(self, config_file):
        """वापरकर्ता-परिभाषित पॅटर्न्स JSON फाइलमधून लोड करते (Loads user-defined patterns from a JSON file if provided)."""
        if not config_file or not os.path.exists(config_file):
            logging.warning(f"User pattern file {config_file} not found. Proceeding with default patterns only.")
            return {}

        try:
            with open(config_file, "r") as file:
                patterns = json.load(file)
                logging.info(f"Successfully loaded patterns from {config_file}: {patterns}")
                return patterns
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from {config_file}: {e}")
            return {}
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading custom patterns: {e}")
            return {}

    def detect_technologies(self, html_content, headers):
        """
        तंत्रज्ञान शोधते वापरकर्ता-परिभाषित पॅटर्न्स आणि डीफॉल्ट पॅटर्न्स तपासून (Detects technologies by checking both user-defined patterns and default patterns).
        """
        technologies = set()  # तंत्रज्ञान संच तयार करा (Create a set to store detected technologies)

        # प्रथम वापरकर्ता-परिभाषित पॅटर्न्स तपासा (Check user-defined patterns first)
        technologies.update(self.detect_from_html(html_content, self.user_patterns.get("html_patterns", {})))
        technologies.update(self.detect_from_headers(headers, self.user_patterns.get("header_patterns", {})))

        # जर वापरकर्ता-परिभाषित पॅटर्न्सने तंत्रज्ञान शोधले तर डीफॉल्ट पॅटर्न्स tapasato (If user-defined patterns already found techs, stop checking default patterns)
        technologies.update(self.detect_from_html(html_content, self.default_patterns["html_patterns"]))
        technologies.update(self.detect_from_headers(headers, self.default_patterns["header_patterns"]))

        logging.info(f"Final detected technologies: {technologies}")  # अंतिम शोधलेले तंत्रज्ञान लॉग करा (Log the final detected technologies)
        return list(technologies)  # तंत्रज्ञानाची यादी परत करा (Return the list of technologies)

    def detect_from_html(self, html_content, patterns):
        technologies = set()

        for tech, pattern in patterns.items():
            if re.search(pattern, html_content, re.IGNORECASE):
                technologies.add(tech)

        return technologies

    def detect_from_headers(self, headers, patterns):
        technologies = set()

        for tech, pattern in patterns.items():
            if re.search(pattern, headers.get('x-powered-by', ''), re.IGNORECASE) or re.search(pattern, headers.get('server', ''), re.IGNORECASE):
                technologies.add(tech)

        return technologies

    def final_function(self, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            html_content = response.text
            headers = response.headers

            detected_tech = self.detect_technologies(html_content, headers)
            return detected_tech
        except requests.RequestException as e:
            logging.error(f"Error fetching the URL: {e}")
            return []
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return []

if __name__ == "__main__":
    # कोणत्याही वेबसाइटचा URL इनपुट घेण्यासाठी तात्पुरती मुख्य फंक्शन (Temporary main function to take the input of the URL of any website)
    url = input("Enter the URL of the website: ")
    try:
        # कस्टम पॅटर्न्ससह TechDetector प्रारंभ करा (Initialize TechDetector with custom patterns)
        detector = TechDetector('custom_patterns.json')  # Initialize with custom patterns file

        # URL वरून तंत्रज्ञान शोधण्यासाठी final_function कॉल करा (Call final_function to detect technologies from the URL)
        detected_tech = detector.final_function(url)
        print("Detected Technologies:", detected_tech)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
