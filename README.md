# Gmail Phishing Email Detector

## About the Project
The **Gmail Phishing Email Detector** is a Chrome Extension integrated with a Python Flask backend that helps users detect phishing emails in their Gmail inbox. The system analyzes email content, URLs, attachments, and keywords. It also supports multi-language detection, providing translations and risk classification.  

This tool is designed to make email security accessible, alerting users about potential phishing attempts in real-time.

## Features
- **Email Body Analysis**: Scans emails for phishing patterns and suspicious content.
- **Attachment Scanning**: Checks all email attachments using VirusTotal and displays results.
- **URL Analysis**: Detects and evaluates URLs inside emails, including VirusTotal checks.
- **Keyword Detection**: Matches phishing and safe keywords for risk assessment.
- **Multi-language Support**: Detects language and translates emails for accurate scanning.
- **Risk Classification**: Emails are classified as `✅ SAFE`, `⚠️ SUSPICIOUS`, or `🚨 PHISHING`.

## Tech Stack
- **Frontend**: Chrome Extension (HTML, CSS, JS)
- **Backend**: Python Flask API
- **APIs & Services**:
  - Gmail API (via Google OAuth)
  - VirusTotal API for attachment and URL scanning
- **Libraries & Packages**:
  - `flask`, `flask_cors`
  - `requests`, `google-api-python-client`, `google-auth`, `google-auth-oauthlib`
  - `langdetect`, `googletrans`
  - `base64`, `hashlib`, `re`, `os`, `time`

## Setup Instructions
- **Install the Chrome Extension**
  - Open Chrome and go to Manage Extensions (chrome://extensions/).
  - Enable Developer Mode (toggle in the top-right corner).
  - Click Load Unpacked (top-left corner).
  - Select the Chrome_Extension folder from your project directory.
  - Ensure the extension is turned on — you should now see the extension icon in the Chrome toolbar.

- **Configure VirusTotal API**
  - Create an account on VirusTotal and generate an API key.
  - Make a note of your API key — you will need it for the backend.
  - Open app.py in the gmail_phishing_detector folder and paste your VirusTotal API key in the appropriate variable:
  - **VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"**

- **Configure Google OAuth**
  - Go to the Google Cloud Console
  - and create a new project.
  - Navigate to APIs & Services → Credentials → Create Credentials → OAuth Client ID.
  - Select Application Type as Chrome Extension.
  - Copy your Extension ID from Chrome (chrome://extensions/) and paste it into the OAuth client creation form.
  - After creation, note down the OAuth Client ID, project ID.
  - Save it in the credentials.json file in your project directory:
  - **{"client_id": "YOUR_OAUTH_CLIENT_ID_HERE" , project_id: "YOUR_PROJECT_ID_HERE"}**

- **Start the Backend Service**
  - Open a terminal in your code editor and navigate to the gmail_phishing_detector folder:
  - cd gmail_phishing_detector
  - Activate the virtual environment (Windows example):
  - **.\venv\Scripts\Activate**
  - Run the Flask backend:
  - python app.py
  - The backend will start and listen on http://localhost:5000.

## Demo Video
[https://drive.google.com/file/d/1GxS-filvyQ6i22N0ZM0jGqFIRNKqxgCa/view?usp=sharing]

## Contribution
- Contributions are welcome! You can:
- Add support for more email providers.
- Improve URL detection algorithms.
- Enhance multi-language support.
- Optimize attachment scanning speed.