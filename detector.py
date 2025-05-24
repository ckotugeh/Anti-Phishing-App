suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 'bank', 'webscr']

def check_url(url: str) -> str:
    if any(word in url.lower() for word in suspicious_keywords):
        return "suspicious"

    # Simulate a check from external phishing API (replace later)
    if "phishingsite" in url:
        return "phishing"

    return "safe"
