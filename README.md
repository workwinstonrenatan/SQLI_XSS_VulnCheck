# Web Vulnerability Scanner SQL Injection and Cross Site Scripting
## Overview
This script is a simple web vulnerability scanner that can detect SQL Injection (SQLi) and Cross-Site Scripting (XSS) vulnerabilities in web forms. It accepts a URL as input, verifies its existence, and then scans the URL for specified vulnerabilities based on user input.

## Features
- URL Existence Check: Verifies if the given URL is reachable.
- Form Detection: Identifies and retrieves all forms from the specified URL.
- SQL Injection Scan: Tests forms for SQL Injection vulnerabilities using various payloads.
- Cross-Site Scripting (XSS) Scan: Tests forms for XSS vulnerabilities by injecting a JavaScript payload.
- Detailed Output: Provides detailed output on the forms tested, the results of the vulnerability scans, and the time needed for the whole process.

## Code Structure
The script is structured into several functions, each responsible for a specific task:
- Library Imports: Necessary libraries are imported at the beginning.
- discover_urls(url): Checks if the given URL is reachable.
- get_forms(url): Fetches all forms from the given URL.
- get_details(form): Extracts and returns details of a form, including action, method, and inputs.
- scan_sqli(url): Scans the URL for SQL Injection vulnerabilities.
- submit_form(form_details, url, value): Submits a form with a given payload.
- scan_xss(url): Scans the URL for XSS vulnerabilities.
- Main Application: Prompts the user for input and coordinates the scanning process.

## Key Decisions
- Modular Design: The script is broken down into modular functions for readability and maintainability.
- Error Handling: Basic error handling is implemented to manage exceptions during URL requests.
- User-Agent Header: A User-Agent header is included in the session to mimic a real browser and avoid basic bot detection mechanisms.
- Payloads: The script uses only 10 payloads, as these are the most common SQL Injection payloads. This approach enhances both time and resource efficiency.
```python
"'", "''", "`", "``", '"', '""', "' or \"", "' OR '1", '" OR "" = "', "' OR '' = '"
```  

## Instructions
### Prerequisites
- Python 3.x
- Required Python libraries: os, sys, requests, beautifulsoup4, urllib3, pprint, datetime
- Install the required Python libraries:
```python
pip install requests beautifulsoup4
```

### Running the Script
- Download the script or copy and paste the script then proceed with saving it, e.g. SQLI_XSS_v1.py.
- Open your favorite code editor and visit the directory where you store the file.
```python
python SQLI_XSS_v1.py
```
- Enter the URL to scan when prompted.
- Choose the type of scan by entering 1 for SQL Injection or 2 for Cross-Site Scripting (XSS).

### Example Usage
```python
Enter URL to scan: https://example.com
The URL https://example.com exists.
__________________________________________________
Enter '1' for SQL Injection
Enter '2' for Cross-Site Scripting (XSS)
Type of scan: 1
__________________________________________________

____________SCANNING FOR SQL INJECTION____________
The url is: https://example.com
[+] Detected 0 forms on https://example.com.
[+] SQL Injection vulnerability is not detected on https://example.com

Scanned at:  20/05/2024 21:33:36
Time taken: 4.758937120437622s
```

## Notes
- This script is intended for educational purposes and should only be used on websites you own or have permission to test.
- Always use such tools responsibly and within the bounds of the law.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
