import re

# Common patterns for hardcoded secrets and API keys
SECRET_PATTERNS = {
    "aws_access_key": r"(?i)AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
    "github_token": r"(?i)gh[pousr]_[A-Za-z0-9_]{36,255}",
    "slack_token": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}",
    "google_api_key": r"AIza[0-9A-Za-z-_]{35}",
    "stripe_key": r"(?i)sk_(live|test)_[0-9a-zA-Z]{24}",
    "generic_password": r"(?i)(password|passwd|pwd|secret)\s*[:=]\s*['\"][^'\"]+['\"]"
}

def scan_for_secrets(text: str) -> dict:
    """
    Scans the given text for exposed secrets or API keys.
    Returns a score, flags, and a sanitized version of the text.
    """
    flags = []
    found_secrets = False
    sanitized_text = text
    
    for secret_type, pattern in SECRET_PATTERNS.items():
        if re.search(pattern, text):
            flags.append({
                "type": "secret_leak",
                "reason": f"CRITICAL: Exposed {secret_type} detected!"
            })
            found_secrets = True
            # Auto-Remediation: Redact the secret
            sanitized_text = re.sub(pattern, f"[REDACTED_{secret_type.upper()}]", sanitized_text)
            
    if found_secrets:
        return {"score": 100, "flags": flags, "sanitized_text": sanitized_text}
    
    return {"score": 0, "flags": [], "sanitized_text": text}
