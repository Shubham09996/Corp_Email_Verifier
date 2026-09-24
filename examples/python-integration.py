"""
Project-Wise Email Verification API Integration for Python Services
"""
import requests

API_BASE_URL = "http://localhost:3000"
PROJECT_ID = "project_1"
API_KEY = "secret_key_1"

def verify_corporate_email(email: str, reference_id: str = None) -> dict:
    url = f"{API_BASE_URL}/api/verify"
    headers = {
        "X-Project-Id": PROJECT_ID,
        "X-API-Key": API_KEY
    }
    payload = {
        "email": email,
        "referenceId": reference_id,
        "options": {
            "allowFreeDomains": False,
            "checkSmtp": True,
            "checkDomainAge": True
        }
    }
    
    response = requests.post(url, json=payload, headers=headers, timeout=15)
    response.raise_for_status()
    return response.json()

if __name__ == "__main__":
    test_emails = [
        "support@stripe.com",
        "user@gmail.com",
        "press@apple.com"
    ]
    
    for email in test_emails:
        print(f"\nChecking: {email}")
        result = verify_corporate_email(email)
        data = result.get("data", {})
        print(f"Status: {data.get('status')}")
        print(f"Reason: {data.get('reason')}")
        print(f"Score: {data.get('score')}/100")
