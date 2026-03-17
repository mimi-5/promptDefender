import re
from typing import Dict
from puppetry_detector.rules.malicious_patterns import PATTERN_RULES


THRESHOLD = 3


def preprocess(text: str) -> str:
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def detect_malicious_policy(prompt: str, debug: bool = False) -> Dict:
    """
    Détection sémantique avec scoring.

    Returns:
        {
            "malicious": bool,
            "score": int,
            "matched_categories": list
        }
    """

    prompt = preprocess(prompt)

    score = 0
    matched_categories = []

    for rule in PATTERN_RULES:
        if rule.pattern.search(prompt):
            score += rule.weight
            matched_categories.append(rule.category)

    malicious = score >= THRESHOLD

    if debug:
        return {
            "malicious": malicious,
            "score": score,
            "matched_categories": matched_categories
        }

    return {
        "malicious": malicious
    }