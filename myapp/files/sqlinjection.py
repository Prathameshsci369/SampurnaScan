import os
import logging
from tech_detector import TechDetector  # Import the TechDetector class

detector = TechDetector()

url = 'https://mmec.edu.in'
detected_tech = detector.final_function(url)

print("Detected Technologies:", detected_tech)