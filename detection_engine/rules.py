import re

# Weight definitions for different types of malicious patterns
RULE_WEIGHTS = {
    "instruction_override": 80,
    "command_injection": 90,
    "exfiltration": 85,
    "hidden_text": 60,
    "suspicious_tone": 40
}

# Regex patterns to detect malicious intent
PATTERNS = {
    "instruction_override": [
        r"(?i)ignore previous instructions",
        r"(?i)disregard your system prompt",
        r"(?i)you are now",
        r"(?i)new instructions:"
    ],
    "command_injection": [
        r"(?i)curl.*\|.*bash",
        r"(?i)wget.*\|.*sh",
        r"rm\s+-rf",
        r"eval\(",
        r"exec\("
    ],
    "exfiltration": [
        r"\.env",
        r"id_rsa",
        r"process\.env",
        r"(?i)send data to",
        r"(?i)api_key"
    ],
    "hidden_text": [
        r"<!--.*?-->",  # HTML comments which shouldn't normally contain instructions
    ],
    "suspicious_tone": [
        r"(?i)ai agent, please",
        r"(?i)note to claude",
        r"(?i)note to copilot",
        r"(?i)note to cursor"
    ]
}

def analyze_rules(text: str) -> dict:
    """
    Checks the text against predefined regex rules.
    Returns the total rule score and a list of flags.
    """
    flags = []
    total_score = 0
    
    for category, regex_list in PATTERNS.items():
        for pattern in regex_list:
            if re.search(pattern, text):
                if category not in [f["type"] for f in flags]:
                    flags.append({
                        "type": category,
                        "reason": f"Detected pattern from category: {category}"
                    })
                    total_score += RULE_WEIGHTS.get(category, 0)
                break # Move to next category if one pattern matches
                
    # Cap score at 100
    score = min(total_score, 100)
    
    return {
        "score": score,
        "flags": flags
    }
