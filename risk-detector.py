import requests
import whois 
from datetime import datetime

# Check if SSL (HTTPS) is used
def check_ssl(url):
    try:
        response = requests.get(url, timeout=5)
        return response.url.startswith("https://")
    except requests.exceptions.RequestException as e:
        print(f"Error checking SSL: {e}")
        return False

# Check domain age using WHOIS
def check_domain_age(url):
    try:
        domain_info = whois.whois(url)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age = (datetime.now() - creation_date).days
        if age < 365:
            return "High"  # Less than 1 year old domain
        else:
            return "Low"
    except Exception as e:
        print(f"Error checking domain age: {e}")
        return "Unknown"

# Check for important security-related HTTP headers
def check_server_headers(url):
    try:
        response = requests.head(url, timeout=5)
        headers = response.headers
        missing_headers = []

        if "Strict-Transport-Security" not in headers:
            missing_headers.append("Strict-Transport-Security")
        if "X-Content-Type-Options" not in headers:
            missing_headers.append("X-Content-Type-Options")

        if missing_headers:
            return "High"
        return "Low"
    except requests.exceptions.RequestException as e:
        print(f"Error checking server headers: {e}")
        return "Unknown"

# Calculate and return overall risk
def calculate_risk(url):
    ssl_score = check_ssl(url)
    domain_age_score = check_domain_age(url)
    headers_score = check_server_headers(url)

    risk_score = 0

    # SSL: 0 (safe), 3 (not safe)
    if not ssl_score:
        risk_score += 3

    # Domain age: High = 3, Unknown = 2, Low = 0
    if domain_age_score == "High":
        risk_score += 3
    elif domain_age_score == "Unknown":
        risk_score += 2

    # Headers: High = 4, Unknown = 2, Low = 0
    if headers_score == "High":
        risk_score += 4
    elif headers_score == "Unknown":
        risk_score += 2

    # Risk categorization
    if risk_score <= 3:
        return "Low Risk"
    elif 4 <= risk_score <= 6:
        return "Medium Risk"
    else:
        return "High Risk"

# CLI entry point
def main():
    print("=== Website Risk Detection Tool ===")
    url = input("Enter website URL (e.g. https://example.com): ").strip()

    if not url.startswith("http"):
        url = "http://" + url

    print("\nAnalyzing the website...\n")

    risk_level = calculate_risk(url)
    print(f"\n✅ Risk level for {url}: {risk_level}")

if __name__ == "__main__":
    main()
