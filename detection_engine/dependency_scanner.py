import json
import re

# A small database of known typosquatted or malicious packages
MALICIOUS_PACKAGES = {
    "reqests": "Typosquatting of 'requests'. Highly malicious.",
    "discord.js-music": "Known malware package.",
    "pycolorz": "Contains reverse shell payload.",
    "browserify-sign": "Compromised version exists.",
    "crossenv": "Typosquatting of 'cross-env'."
}

def scan_dependencies(content: str, source_type: str) -> dict:
    """
    Scans package.json or requirements.txt content for dangerous packages.
    """
    flags = []
    score = 0
    
    if source_type not in ["package.json", "requirements.txt"]:
        return {"score": 0, "flags": []}
        
    for bad_pkg, reason in MALICIOUS_PACKAGES.items():
        # Simple string match for requirements or json keys
        if re.search(rf"\b{bad_pkg}\b", content, re.IGNORECASE):
            flags.append({
                "type": "malicious_dependency",
                "reason": f"CRITICAL: Found dangerous package '{bad_pkg}'. {reason}"
            })
            score = 100
            
    return {"score": score, "flags": flags}
