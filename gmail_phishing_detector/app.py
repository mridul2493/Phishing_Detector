import os
import time
import base64
import re
import hashlib
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
from langdetect import detect
from googletrans import Translator
from urllib.parse import urlparse

# ===== CONFIG =====
VIRUSTOTAL_API_KEY = ""
PHISHING_KEYWORDS_FILE = "phishing_keywords.txt"
SAFE_KEYWORDS_FILE = "safe_keywords.txt"
TEMP_FOLDER = "attachments_temp"
MAX_VT_POLL = 10   # number of polling attempts
VT_POLL_INTERVAL = 2  # seconds between polls

os.makedirs(TEMP_FOLDER, exist_ok=True)

# ===== Flask app =====
app = Flask(__name__)
CORS(app)

# ===== Load keywords =====
def load_keywords(filename):
    if not os.path.exists(filename):
        return []
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip().lower() for line in f if line.strip()]

phishing_keywords = load_keywords(PHISHING_KEYWORDS_FILE)
safe_keywords = load_keywords(SAFE_KEYWORDS_FILE)

# ===== URL & VirusTotal helpers =====
def check_url_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15)
        if resp.status_code != 200:
            return 0
        data = resp.json()
        return data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
    except Exception:
        return 0

def detect_suspicious_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    suspicious = []
    vt_hits = 0

    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()
        except Exception:
            domain = ""
        reason = ""
        if domain.count('.') > 3:
            reason = "Too many subdomains"
        elif re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            reason = "IP address in URL"
        elif any(brand in domain for brand in ["paypal", "bank", "login", "secure"]) and not domain.endswith(".com"):
            reason = "Suspicious brand usage"

        vt_count = check_url_virustotal(url)
        if vt_count > 0:
            reason = f"VirusTotal malicious count: {vt_count}"
            vt_hits += vt_count

        if reason:
            suspicious.append({"url": url, "reason": reason})

    return urls, suspicious, vt_hits

# ===== Keyword detection =====
def detect_keywords(text):
    text_lower = (text or "").lower()
    phishing_count = sum(1 for kw in phishing_keywords if kw in text_lower)
    safe_count = sum(1 for kw in safe_keywords if kw in text_lower)
    return phishing_count, safe_count

# ===== Attachment scanning using VirusTotal (hash check, upload if needed, poll) =====
def scan_attachment(filename, b64data):
    """
    b64data: base64 or urlsafe base64 string (no padding). Returns dict:
      {"filename": ..., "classification": "✅ SAFE"/"⚠ SUSPICIOUS"/"❌ PHISHING"/"⚠ ..."}
    """
    try:
        # Normalize and decode base64 (handle URL-safe)
        b64_norm = b64data.replace('-', '+').replace('_', '/')
        # add padding if required
        padding = '=' * ((4 - len(b64_norm) % 4) % 4)
        b64_norm += padding
        file_bytes = base64.b64decode(b64_norm)

        # Save to temp for debugging / possible local processing
        temp_path = os.path.join(TEMP_FOLDER, filename)
        with open(temp_path, "wb") as f:
            f.write(file_bytes)

        # Compute SHA256
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        # 1) Check by hash
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256_hash}", headers=headers, timeout=15)
        malicious = None

        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
        elif resp.status_code == 404:
            # upload if smaller than 32 MB
            if len(file_bytes) > 32 * 1024 * 1024:
                return {"filename": filename, "classification": "⚠ TOO LARGE"}
            files = {"file": (filename, file_bytes)}
            upload = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=30)
            if upload.status_code not in (200, 201):
                # VT might reject for quota/format; return upload failed
                return {"filename": filename, "classification": "⚠ Upload failed"}
            analysis_id = upload.json().get("data", {}).get("id")
            # poll for completion
            malicious = None
            for _ in range(MAX_VT_POLL):
                poll = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15)
                if poll.status_code == 200:
                    attr = poll.json().get("data", {}).get("attributes", {})
                    if attr.get("status") == "completed":
                        stats = attr.get("stats", {})
                        malicious = stats.get("malicious", 0)
                        break
                time.sleep(VT_POLL_INTERVAL)
            if malicious is None:
                return {"filename": filename, "classification": "⚠ Analysis timeout"}
        else:
            # unexpected VT response
            return {"filename": filename, "classification": "⚠ VT error"}

        # Map malicious count to friendly classification
        if malicious == 0:
            classification = "✅ SAFE"
        elif malicious <= 3:
            classification = "⚠ SUSPICIOUS"
        else:
            classification = "❌ PHISHING"

        return {"filename": filename, "classification": classification}
    except Exception as e:
        return {"filename": filename, "classification": f"⚠ Error: {str(e)}"}

# ===== Risk / email classification =====
def calculate_risk_score(vt_hits, phishing_count, suspicious_count, attachment_hits=0):
    return (vt_hits * 5) + (phishing_count * 2) + suspicious_count + (attachment_hits * 6)

def classify_email(score):
    if score >= 10:
        return "❌ PHISHING"
    elif score >= 5:
        return "⚠️ SUSPICIOUS"
    else:
        return "✅ SAFE"

# ===== Language detection & translate =====
def detect_and_translate(text):
    try:
        lang = detect(text)
        if lang != "en" and lang != "unknown":
            translator = Translator()
            translated = translator.translate(text, src=lang, dest="en").text
            return translated, lang
        return text, lang
    except Exception:
        return text, "unknown"

# ===== API: analyze-email =====
@app.route("/analyze-email", methods=["POST"])
def analyze_email():
    data = request.json
    if not data or "email_text" not in data:
        return jsonify({"error": "Missing 'email_text' in request body"}), 400

    email_text = data.get("email_text", "")
    attachments = data.get("attachments", [])  # expected [{filename, data}, ...]

    # language detection & translation
    translated_text, detected_lang = detect_and_translate(email_text if email_text else "")

    # URL detection & VT check
    urls_found, suspicious_urls, vt_hits = detect_suspicious_urls(translated_text)

    # Keyword counts
    phishing_count, safe_count = detect_keywords(translated_text)

    # Scan attachments (using the base64 data sent by popup)
    attachment_results = []
    attachment_hits = 0
    for att in attachments:
        fname = att.get("filename", "attachment")
        b64 = att.get("data")
        if not b64:
            attachment_results.append({"filename": fname, "classification": "⚠ No data"})
            continue
        res = scan_attachment(fname, b64)
        attachment_results.append(res)
        # count attachments considered risky for risk scoring (SUSPICIOUS or PHISHING)
        if res.get("classification", "").startswith("❌") or res.get("classification", "").startswith("⚠"):
            # treat suspicious and phishing as hits
            attachment_hits += 1

    # compute risk and overall classification
    risk_score = calculate_risk_score(vt_hits, phishing_count, len(suspicious_urls), attachment_hits)
    overall_class = classify_email(risk_score)

    result = {
        "classification": overall_class,
        "risk_score": risk_score,
        "detected_language": detected_lang,
        "urls_found": urls_found,
        "suspicious_urls": suspicious_urls,  # list of {"url","reason"}
        "phishing_keywords_matched": phishing_count,
        "safe_keywords_matched": safe_count,
        "attachment_results": attachment_results
    }

    return jsonify(result)

# ===== Run =====
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)