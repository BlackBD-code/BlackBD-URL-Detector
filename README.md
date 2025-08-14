# BlackBD Advanced URL Phishing Detector

This is an advanced Python-based tool designed to detect potential phishing and malicious URLs. It performs multiple checks to ensure a link is safe, including:

- **Google Safe Browse API:** Checks the URL against Google's real-time database of unsafe websites.
- **Typosquatting Detection:** Uses the Levenshtein distance algorithm to find URLs that are very similar to trusted domains (e.g., `gooogle.com`).
- **Domain Age Check:** Analyzes the domain's registration date, as very new domains are often used for phishing.
- **Suspicious Patterns:** Scans for suspicious keywords and file extensions (e.g., `.apk`, `.exe`) within the URL.

## Installation

First, clone this repository to your local machine:
```bash
git clone YOUR_REPOSITORY_URL
cd your_project_folder
Then, install the necessary Python libraries by running this command:
pip install -r requirements.txt

Setup: Get Your Google Safe Browse API Key
To use the Google Safe Browse feature, you need to get a free API key from Google.
Go to the Google Cloud Console.
Create a new project.
Navigate to the "APIs & Services" > "Library" and search for "Safe Browse API".
Enable the API for your project.
Go to "Credentials" and create an API key.
Usage
Before running the tool, you must set your API key as an environment variable.

For macOS and Linux
export GOOGLE_SAFE_Browse_API_KEY="YOUR_API_KEY_HERE"
For Windows
setx GOOGLE_SAFE_Browse_API_KEY "YOUR_API_KEY_HERE"

Now, you can run the tool from your terminal:
python blackbd_url_detector.py