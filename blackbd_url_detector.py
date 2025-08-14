import requests
import re
import time
import datetime
from urllib.parse import urlparse
from termcolor import colored
from pyfiglet import Figlet
from googleapiclient.discovery import build
import Levenshtein
import whois

# --- Configuration and Data ---
GOOGLE_SAFE_Browse_API_KEY = ""  # Replace with your actual API Key

# A list of trusted domains for typosquatting checks.
TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "microsoft.com", 
    "apple.com", "linkedin.com", "twitter.com", "wikipedia.org",
    "paypal.com", "netflix.com", "ebay.com", "instagram.com"
]

# A list of suspicious file extensions that are often used for malware.
SUSPICIOUS_EXTENSIONS = [
    ".apk", ".exe", ".dmg", ".sh", ".bat", ".vbs", ".js", ".bin"
]

# A list of keywords that often appear in malicious file names.
SUSPICIOUS_KEYWORDS = [
    "malware", "virus", "trojan", "rat", "phish", "hack", "download"
]


def print_banner():
    """Prints a stylized banner for the BlackBD tool."""
    f = Figlet(font='slant')
    print(colored(f.renderText('BlackBD'), 'cyan'))
    print(colored("--- Advanced URL Phishing Detector ---", 'green'))


def check_google_safe_Browse(url):
    """
    Checks a URL against the Google Safe Browse API.
    Returns True if the URL is a known threat, False otherwise.
    """
    try:
        service = build('safeBrowse', 'v4', developerKey=GOOGLE_SAFE_Browse_API_KEY)
        request_body = {
            "client": {
                "clientId": "your_app_name", # You can put any name here
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = service.threatMatches().find(body=request_body).execute()
        return bool(response)  # Returns True if any matches are found
    except Exception as e:
        print(colored(f"Error checking Google Safe Browse API: {e}", 'red'))
        return False


def is_typosquatting(url):
    """
    Detects typosquatting using Levenshtein distance.
    Returns True if the domain is very similar to a trusted domain.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.replace('www.', '').lower()
        for trusted_domain in TRUSTED_DOMAINS:
            # Calculate similarity. A small distance means a high similarity.
            distance = Levenshtein.distance(domain, trusted_domain)
            if distance <= 2 and len(domain) == len(trusted_domain):
                return True, f"The domain '{domain}' is a possible typosquatting attempt of '{trusted_domain}'."
        return False, ""
    except Exception:
        return False, ""


def check_domain_age(url):
    """
    Checks the age of the domain. Returns True if the domain is less than 30 days old.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            return False, ""

        w = whois.whois(domain)
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date

        if creation_date:
            age = (datetime.datetime.now() - creation_date).days
            if age < 30:
                return True, f"The domain is very new (created {age} days ago). This is a common sign of a phishing domain."
        return False, ""
    except whois.parser.PywhoisError:
        return False, "Could not retrieve domain registration date."
    except Exception as e:
        return False, f"An error occurred while checking domain age: {e}"


def is_phishing(url):
    """
    Combines all phishing detection methods into one function.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path.lower()

        # 1. Check for IP address in the domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            return True, "IP address found in the domain name. This is highly suspicious."
        
        # 2. Check for multiple hyphens in the domain
        if domain.count('-') > 2:
            return True, "Multiple hyphens found in the domain. This could be a phishing attempt."

        # 3. Check for suspicious file extensions
        for ext in SUSPICIOUS_EXTENSIONS:
            if path.endswith(ext):
                return True, f"The URL links to a file with a suspicious extension ({ext}). This could be malware."

        # 4. Check for suspicious keywords in the path
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in path:
                return True, f"The URL path contains a suspicious keyword: '{keyword}'."
        
        # New advanced checks
        is_typo, typo_msg = is_typosquatting(url)
        if is_typo:
            return True, typo_msg
        
        is_new_domain, new_domain_msg = check_domain_age(url)
        if is_new_domain:
            return True, new_domain_msg

        return False, "The URL appears to be safe based on initial analysis."
        
    except Exception as e:
        return False, f"An error occurred during phishing check: {e}"


def get_final_url(url):
    """
    Follows redirects to find the final URL of a given link.
    """
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        return response.url
    except requests.exceptions.RequestException:
        return url

def main():
    """
    The main function for the BlackBD URL Detector tool with all features.
    """
    print_banner()
    print(colored("Welcome to the BlackBD Advanced URL Detector!", 'yellow'))
    print(colored("Please enter a link, and I will perform a comprehensive scan.", 'yellow'))
    print(colored("Type 'exit' to quit.", 'red'))

    while True:
        user_input = input(colored("\nEnter a link: ", 'cyan'))
        if user_input.lower() == 'exit':
            break

        if not user_input.startswith(('http://', 'https://')):
            print(colored("Invalid link. Please make sure it starts with http:// or https://.", 'red'))
            continue
        
        print(colored(f"\nScanning... {user_input}", 'magenta'), end='', flush=True)
        for _ in range(3):
            time.sleep(0.5)
            print(colored('.', 'magenta'), end='', flush=True)
        print()
        
        # --- Run Advanced Checks ---
        print(colored("Checking Google Safe Browse...", 'yellow'))
        is_google_phishing = check_google_safe_Browse(user_input)
        if is_google_phishing:
            print(colored("\n🚨🚨 CRITICAL WARNING: GOOGLE SAFE Browse IDENTIFIED THIS URL AS A KNOWN THREAT! 🚨🚨", 'red', attrs=['bold']))
            continue
        print(colored("✅ Not found in Google Safe Browse database.", 'green'))
        
        print(colored("Performing pattern analysis...", 'yellow'))
        is_phishing_link, message = is_phishing(user_input)
        if is_phishing_link:
            print(colored("\n🚨🚨 WARNING: POSSIBLE PHISHING URL DETECTED! 🚨🚨", 'red', attrs=['bold']))
            print(colored(f"Reason: {message}", 'red'))
            continue

        final_url = get_final_url(user_input)
        print(colored(f"\nFinal URL: {final_url}", 'green'))
        
        is_final_phishing, final_message = is_phishing(final_url)
        is_google_final_phishing = check_google_safe_Browse(final_url)

        if is_final_phishing or is_google_final_phishing:
            print(colored("\n🚨🚨 WARNING: THE FINAL DESTINATION URL IS POTENTIALLY PHISHING! 🚨🚨", 'red', attrs=['bold']))
            if is_final_phishing:
                print(colored(f"Reason: {final_message}", 'red'))
            if is_google_final_phishing:
                print(colored("Reason: Found in Google Safe Browse database.", 'red'))
        else:
            print(colored("\n✅ This URL appears to be safe.", 'green'))


if __name__ == "__main__":
    main()

