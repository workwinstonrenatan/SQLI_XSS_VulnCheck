# Import libraries needed
import os
import sys
import requests
import time
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from datetime import datetime

# Look up for the existance of URL
def discover_urls(url):
    try:
        response = requests.head(url, allow_redirects=True)
        # Check if the status code is 200 (OK)
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        # Print the exception if needed
        print(e)
        return False

# Captures all "form" in the URL function
def get_forms(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

# Get all the information about a "form"
def get_details(form):
    details = {}
    # Start the action
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # POST & GET Method
    method = form.attrs.get("method", "get").lower()
    # Input Name and Type
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # Save details into variables accordingly
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# Scan for SQLI function
def scan_sqli(url):
    def is_vulnerable(response):
        errors = {
            # MySQL
            "you have an error in your sql syntax;",
            "warning: mysql",
            # SQL Server
            "unclosed quotation mark after the character string",
            # Oracle
            "quoted string not properly terminated",
        }
        for error in errors:
            # Error is found
            if error in response.content.decode().lower():
                return True
        # Error is not found
        return False
    
    print("The url is:", url)
    # Checker value
    is_sqli_vulnerable = False
    # Check through all forms for SQLI vulnerability
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_details(form)
        # Adjustment by adding payload in URL to be processed
        sqli_payload = ["'", "''", "`", "``", '"', '""', "' or \"", "' OR '1", '" OR "" = "', "' OR '' = '"]
        for item in sqli_payload:
            new_url = f"{url}{item}"
            print("[!] Trying", new_url)
            # HTTP request creation
            res = s.get(new_url)
            # Check for the response
            if is_vulnerable(res):
                is_sqli_vulnerable = True
                print("[+] SQL Injection vulnerability detected on", url)
                print("[+] Form details:")
                pprint(form_details)
                break
    if is_sqli_vulnerable is False:
        print(f"[+] SQL Injection vulnerability is not detected on {url}")
    # Record additional timestamp information
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    end = time.time()
    print("\nScanned at: ", dt_string)
    print(f"Time taken: {end - start}s")

# Do a form submission trying for XSS
def submit_form(form_details, url, value):
    # URL and details
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # change text and search = `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value exist, add it in form
            data[input_name] = input_value
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # Capture Requests
        return requests.get(target_url, params=data)

# Scan for XSS function
def scan_xss(url):
    print("The url is:", url)
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<script>alert('XSS vulnerability is here!')</script>"
    # Checker value
    is_xss_vulnerable = False
    # Check through all forms for XSS vulnerability
    for form in forms:
        form_details = get_details(form)
        # Perform payload injection to form
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS vulnerability detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_xss_vulnerable = True
    if is_xss_vulnerable is False:
        print(f"[+] XSS vulnerability is not detected on {url}")
    # Record additional timestamp information
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    end = time.time()
    print("\nScanned at: ", dt_string)
    print(f"Time taken: {end - start}s")
    return is_xss_vulnerable

# _________________MAIN APPLICATION_________________
# Enter URL that is going to be scanned
url = input("Enter URL to scan: ")
if discover_urls(url):
    print(f"The URL {url} exists.")
else:
    print(f"The URL {url} does not exist.")
    exit()
# Enter options of scanning SQLI/XSS
print("__________________________________________________")
print("Enter '1' for SQL Injection")
print("Enter '2' for Cross-Site Scripting (XSS)")
scan_choice = input("Type of scan: ")
print("__________________________________________________\n")
# Set a new Session (HTTP)
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36 "

# Scan for SQLI in the given URL
if scan_choice == '1':
    print("____________SCANNING FOR SQL INJECTION____________")
    # Record process start time
    start = time.time()
    # Calls SQLI scan function
    scan_sqli(url)

# Scan for XSS in the given URL
elif scan_choice == '2':
    print("_________________SCANNING FOR XSS_________________")
    # Record process start time
    start = time.time()
    # Calls XSS scan function
    scan_xss(url)

# Application breaks as it does not match any given options
else:
    print("___________________PROGRAM QUIT___________________")