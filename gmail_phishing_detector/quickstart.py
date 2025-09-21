from __future__ import print_function
import re
from urllib.parse import urlparse
import base64
import os
import requests
import hashlib
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from langdetect import detect, detect_langs
from googletrans import Translator

# ==== CONFIG ====
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
VIRUSTOTAL_API_KEY = "70fa29358e926bbcff5aa05a3e22705f4ab13c03580680265b9c92538c8c1957"
PHISHING_KEYWORDS_FILE = "phishing_keywords.txt"
SAFE_KEYWORDS_FILE = "safe_keywords.txt"
TEMP_FOLDER = "attachments_temp"

os.makedirs(TEMP_FOLDER, exist_ok=True)

# === Load keyword lists ===
def load_keywords(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]

phishing_keywords = load_keywords(PHISHING_KEYWORDS_FILE)
safe_keywords = load_keywords(SAFE_KEYWORDS_FILE)

# === Gmail Auth ===
def get_gmail_service():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

# === VirusTotal URL check ===
def check_url_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if response.status_code == 404:
            return 0
        data = response.json()
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    except:
        return 0

# === VirusTotal File Hash Check ===
def check_file_virustotal(file_path):
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
        if response.status_code == 404:
            return 0
        data = response.json()
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    except:
        return 0

# === Detect URLs ===
def detect_suspicious_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    suspicious = []
    vt_hits = 0

    for url in urls:
        domain = urlparse(url).netloc.lower()
        if domain.count('.') > 3:
            suspicious.append((url, "Too many subdomains"))
        elif re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            suspicious.append((url, "IP address in URL"))
        elif any(brand in domain for brand in ["paypal", "bank", "login", "secure"]) and not domain.endswith(".com"):
            suspicious.append((url, "Suspicious brand usage"))

        vt_result = check_url_virustotal(url)
        if vt_result > 0:
            suspicious.append((url, f"VirusTotal malicious count: {vt_result}"))
            vt_hits += vt_result

    return urls, suspicious, vt_hits

# === Keyword detection ===
def detect_keywords(text):
    text_lower = text.lower()
    phishing_count = sum(1 for kw in phishing_keywords if kw in text_lower)
    safe_count = sum(1 for kw in safe_keywords if kw in text_lower)
    return phishing_count, safe_count

# === Risk Score calculation ===
def calculate_risk_score(vt_hits, phishing_count, suspicious_count, attachment_hits):
    return (vt_hits * 5) + (phishing_count * 2) + suspicious_count + (attachment_hits * 6)

def classify_email(score):
    if score >= 10:
        return "🚨 PHISHING"
    elif score >= 5:
        return "⚠️ SUSPICIOUS"
    else:
        return "✅ SAFE"

# === Language detection & translation ===
def detect_and_translate(text):
    try:
        lang = detect(text)
        if lang != "en":
            translator = Translator()
            translated_text = translator.translate(text, src=lang, dest="en").text
            print(f"🌐 Detected language: {lang} → Translated to English.")
            return translated_text
        return text
    except:
        return text

# === Main Gmail fetch ===
def get_emails(service, max_results=5):
    results = service.users().messages().list(userId='me', maxResults=max_results).execute()
    messages = results.get('messages', [])

    if not messages:
        print("No messages found.")
        return

    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id'], format='full').execute()
        headers = msg_data['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "(No Subject)")
        sender = next((h['value'] for h in headers if h['name'] == 'From'), "(No Sender)")

        # Email body
        if 'parts' in msg_data['payload']:
            data = msg_data['payload']['parts'][0]['body'].get('data')
        else:
            data = msg_data['payload']['body'].get('data')
        body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore') if data else "(No Body)"

        # Translate non-English body
        body = detect_and_translate(body)

        # URL + keyword analysis
        urls, suspicious_urls, vt_hits = detect_suspicious_urls(body)
        phishing_count, safe_count = detect_keywords(body)

        # Attachment scanning
        attachment_hits = 0
        if 'parts' in msg_data['payload']:
            for part in msg_data['payload']['parts']:
                if part.get("filename"):
                    att_id = part['body'].get('attachmentId')
                    if att_id:
                        att = service.users().messages().attachments().get(userId='me', messageId=msg['id'], id=att_id).execute()
                        file_data = base64.urlsafe_b64decode(att['data'])
                        file_path = os.path.join(TEMP_FOLDER, part["filename"])
                        with open(file_path, "wb") as f:
                            f.write(file_data)
                        vt_file_hits = check_file_virustotal(file_path)
                        if vt_file_hits > 0:
                            attachment_hits += vt_file_hits
                            print(f"⚠️ Malicious attachment detected in {part['filename']} ({vt_file_hits} detections on VT)")
                        else:
                            print(f"✅ Attachment {part['filename']} scanned: SAFE")

        # Risk score
        risk_score = calculate_risk_score(vt_hits, phishing_count, len(suspicious_urls), attachment_hits)
        classification = classify_email(risk_score)

        # Output
        print("="*50)
        print(f"From: {sender}")
        print(f"Subject: {subject}")
        print(f"Classification: {classification} (Score: {risk_score})")
        if urls:
            print("URLs found:", urls)
        if suspicious_urls:
            print("Suspicious URLs:")
            for url, reason in suspicious_urls:
                print(f" - {url} ({reason})")
        if attachment_hits > 0:
            print(f"⚠️ Total malicious attachments: {attachment_hits}")
        print(f"Phishing keywords matched: {phishing_count}, Safe keywords matched: {safe_count}")
        print("="*50)

if __name__ == '__main__':
    service = get_gmail_service()
    get_emails(service, max_results=5)