import requests
import json

# Test the phishing detector API
BASE_URL = "http://127.0.0.1:5000"

def test_phishing_email():
    """Test with a sample phishing email"""
    phishing_email = """
    URGENT: Your PayPal account has been suspended!
    
    Dear Customer,
    
    We have detected suspicious activity on your account. To restore access, please click the link below immediately:
    
    http://paypal-security-verify.malicious-site.com/login
    
    If you don't act within 24 hours, your account will be permanently closed.
    
    Enter your username, password, and social security number to verify your identity.
    
    This is urgent! Act now to avoid losing access to your funds.
    
    Best regards,
    PayPal Security Team
    """
    
    response = requests.post(f"{BASE_URL}/analyze-email", 
                           json={"email_text": phishing_email})
    
    print("=== PHISHING EMAIL TEST ===")
    print("Email content:", phishing_email[:100] + "...")
    print("Response:", json.dumps(response.json(), indent=2))
    print()

def test_legitimate_email():
    """Test with a legitimate email"""
    legitimate_email = """
    Meeting Reminder: Project Review Tomorrow
    
    Hi Team,
    
    Just a friendly reminder that we have our monthly project review meeting tomorrow at 2 PM in Conference Room A.
    
    Agenda:
    - Progress updates
    - Budget review
    - Next quarter planning
    
    Please bring your status reports.
    
    Thanks,
    John Smith
    Project Manager
    """
    
    response = requests.post(f"{BASE_URL}/analyze-email", 
                           json={"email_text": legitimate_email})
    
    print("=== LEGITIMATE EMAIL TEST ===")
    print("Email content:", legitimate_email[:100] + "...")
    print("Response:", json.dumps(response.json(), indent=2))
    print()

def test_url_detection():
    """Test URL detection with suspicious URLs"""
    email_with_urls = """
    Check out these links:
    
    Legitimate site: https://www.google.com
    Suspicious IP: http://192.168.1.100/login
    Too many subdomains: https://fake.phishing.suspicious.paypal.com/verify
    
    Click here to verify your account!
    """
    
    response = requests.post(f"{BASE_URL}/analyze-email", 
                           json={"email_text": email_with_urls})
    
    print("=== URL DETECTION TEST ===")
    print("Email content:", email_with_urls[:100] + "...")
    print("Response:", json.dumps(response.json(), indent=2))
    print()

if __name__ == "__main__":
    print("Testing Phishing Detector API...")
    print("=" * 50)
    
    try:
        test_phishing_email()
        test_legitimate_email()
        test_url_detection()
        print("All tests completed successfully!")
    except requests.exceptions.ConnectionError:
        print("Error: Could not connect to the API. Make sure the Flask app is running on http://127.0.0.1:5000")
    except Exception as e:
        print(f"Error during testing: {e}")