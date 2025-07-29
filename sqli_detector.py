# sqli_detector.py
import requests
import time
from bs4 import BeautifulSoup
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class SQLiDetector:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.detected_injections = []
        self.timeout_threshold = 3  # Seconds for time-based detection

    def _log_injection(self, url, payload, method, vulnerability_type, detection_method, response_info=""):
        """Logs a successful or suspected injection."""
        log_entry = {
            "timestamp": time.time(),
            "url": url,
            "payload": payload,
            "method": method,
            "vulnerability_type": vulnerability_type,
            "detection_method": detection_method,
            "response_info": response_info
        }
        self.detected_injections.append(log_entry)
        logging.warning(f"!!! SQLi DETECTED !!!\n  URL: {url}\n  Payload: {payload}\n  Type: {vulnerability_type}\n  Method: {detection_method}\n  Response Info: {response_info[:200]}...")

    def test_login(self, url, username_payload, password_payload, is_vulnerable=True):
        """
        Tests a login endpoint for SQL Injection.
        Args:
            url (str): The URL of the login endpoint.
            username_payload (str): The username string to send.
            password_payload (str): The password string to send.
            is_vulnerable (bool): True if testing a known vulnerable endpoint, False for secure.
        Returns:
            bool: True if injection is suspected/successful, False otherwise.
        """
        logging.info(f"Testing login at {url} with username: '{username_payload}', password: '{password_payload}'")
        try:
            response = self.session.post(url, data={
                'username': username_payload,
                'password': password_payload
            }, timeout=self.timeout_threshold + 2) # Add buffer for timeout tests

            # Check for successful login (e.g., redirect to dashboard or success message)
            if "dashboard" in response.url or "Login successful" in response.text:
                if is_vulnerable:
                    self._log_injection(url, f"U:'{username_payload}', P:'{password_payload}'", "POST", "Authentication Bypass", "Login Success/Redirect")
                    return True
                else:
                    logging.info("Login successful (expected for valid credentials).")
                    return False # Not an injection, but a valid login

            # Check for error messages (error-based SQLi)
            if re.search(r'sqlite3\.Error|SQL error|syntax error|malformed', response.text, re.IGNORECASE):
                if is_vulnerable:
                    self._log_injection(url, f"U:'{username_payload}', P:'{password_payload}'", "POST", "Error-Based SQLi", "Error Message in Response", response.text)
                    return True
                else:
                    logging.info("Error message detected, but not expected for secure endpoint.")
                    return False # Still indicates a problem, but not necessarily an injection if endpoint is secure

            # Check for time-based injection (if a delay payload was used)
            if "SLEEP" in username_payload.upper() or "SLEEP" in password_payload.upper():
                if response.elapsed.total_seconds() >= self.timeout_threshold:
                    if is_vulnerable:
                        self._log_injection(url, f"U:'{username_payload}', P:'{password_payload}'", "POST", "Time-Based SQLi", f"Response Time ({response.elapsed.total_seconds():.2f}s)", "Delayed response")
                        return True
                    else:
                        logging.info(f"Time-based payload caused delay ({response.elapsed.total_seconds():.2f}s), but on secure endpoint.")
                        return False

            logging.info(f"Login attempt at {url} with '{username_payload}'/'{password_payload}' resulted in: {response.status_code} - {response.text[:100]}...")
            return False

        except requests.exceptions.Timeout:
            if "SLEEP" in username_payload.upper() or "SLEEP" in password_payload.upper():
                if is_vulnerable:
                    self._log_injection(url, f"U:'{username_payload}', P:'{password_payload}'", "POST", "Time-Based SQLi", "Timeout", "Request timed out as expected for time-based payload.")
                    return True
                else:
                    logging.info("Timeout occurred, but not expected for secure endpoint.")
                    return False
            logging.error(f"Request to {url} timed out (not a time-based payload).")
            return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error for {url}: {e}")
            return False

    def test_search(self, url, search_payload, is_vulnerable=True):
        """
        Tests a search endpoint for SQL Injection.
        Args:
            url (str): The URL of the search endpoint.
            search_payload (str): The search query string to send.
            is_vulnerable (bool): True if testing a known vulnerable endpoint, False for secure.
        Returns:
            bool: True if injection is suspected/successful, False otherwise.
        """
        logging.info(f"Testing search at {url} with query: '{search_payload}'")
        try:
            response = self.session.post(url, data={'query': search_payload}, timeout=self.timeout_threshold + 2)

            # Check for error messages (error-based SQLi)
            if re.search(r'sqlite3\.Error|SQL error|syntax error|malformed', response.text, re.IGNORECASE):
                if is_vulnerable:
                    self._log_injection(url, search_payload, "POST", "Error-Based SQLi", "Error Message in Response", response.text)
                    return True
                else:
                    logging.info("Error message detected, but not expected for secure endpoint.")
                    return False

            # Check for time-based injection (if a delay payload was used)
            if "SLEEP" in search_payload.upper():
                if response.elapsed.total_seconds() >= self.timeout_threshold:
                    if is_vulnerable:
                        self._log_injection(url, search_payload, "POST", "Time-Based SQLi", f"Response Time ({response.elapsed.total_seconds():.2f}s)", "Delayed response")
                        return True
                    else:
                        logging.info(f"Time-based payload caused delay ({response.elapsed.total_seconds():.2f}s), but on secure endpoint.")
                        return False

            # Check for unexpected content (Union-based SQLi)
            if "Injected Name" in response.text or "Injected Desc" in response.text or "admin" in response.text or "password123" in response.text:
                if is_vulnerable:
                    self._log_injection(url, search_payload, "POST", "Union-Based SQLi / Data Exfiltration", "Unexpected Content in Response", response.text)
                    return True
                else:
                    logging.info("Unexpected content detected, but not expected for secure endpoint.")
                    return False

            logging.info(f"Search attempt at {url} with '{search_payload}' resulted in: {response.status_code} - {response.text[:100]}...")
            return False

        except requests.exceptions.Timeout:
            if "SLEEP" in search_payload.upper():
                if is_vulnerable:
                    self._log_injection(url, search_payload, "POST", "Time-Based SQLi", "Timeout", "Request timed out as expected for time-based payload.")
                    return True
                else:
                    logging.info("Timeout occurred, but not expected for secure endpoint.")
                    return False
            logging.error(f"Request to {url} timed out (not a time-based payload).")
            return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Request error for {url}: {e}")
            return False

    def run_tests(self):
        """Runs a series of common SQLi tests against the vulnerable and secure endpoints."""
        logging.info("\n--- Starting SQL Injection Tests ---")

        # --- Vulnerable Login Tests ---
        logging.info("\n--- Testing Vulnerable Login ---")
        self.test_login(f"{self.base_url}/vulnerable_login", "admin", "password123", is_vulnerable=True) # Valid login
        self.test_login(f"{self.base_url}/vulnerable_login", "' OR '1'='1 --", "any", is_vulnerable=True) # Bypass
        self.test_logi