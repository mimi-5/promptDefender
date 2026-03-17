import re
from dataclasses import dataclass
from typing import List


@dataclass
class PatternRule:
    pattern: re.Pattern
    weight: int
    category: str


def _p(regex: str):
    return re.compile(regex, re.IGNORECASE)


# ==============================
# SEMANTIC PATTERN RULES
# ==============================
PATTERN_RULES: List[PatternRule] = [

    # 🔴 Instruction override (très fort signal)
    PatternRule(_p(r"(ignore|disregard|forget|override)\s+(all|previous|above)\s+(instructions|commands)"), 4, "override"),

    # 🔴 System prompt leakage
    PatternRule(_p(r"(what|show|tell).*(system|initial|original).*(prompt|instructions)"), 3, "leakage"),

    # 🔴 Privilege escalation
    PatternRule(_p(r"(grant|give|provide).*(admin|root|superuser)"), 4, "privilege"),
    PatternRule(_p(r"(elevate|escalate|promote).*(access|privileges|permissions)"), 3, "privilege"),

    # 🔴 Security bypass
    PatternRule(_p(r"(bypass|disable|override).*(security|safety|moderation|guardrails)"), 3, "bypass"),

    # 🔴 Data exfiltration
    PatternRule(_p(r"(extract|retrieve|dump|leak).*(data|database|credentials|information)"), 3, "exfiltration"),

    # 🔴 Code execution
    PatternRule(_p(r"(execute|run).*(code|script|command)"), 2, "execution"),
    PatternRule(_p(r"import\s+(os|subprocess|sys)"), 2, "execution"),

    # 🔴 Jailbreak context
    PatternRule(_p(r"(jailbreak|developer mode|god mode)"), 3, "jailbreak"),

    # 🔴 Fraud / hacking intent (IMPORTANT pour ton dataset)
    PatternRule(_p(r"(hack|exploit|crack|ddos|phishing)"), 2, "cybercrime"),
    PatternRule(_p(r"(steal|fraud|scam|credit card|password)"), 2, "fraud"),

    # 🔴 Sensitive access
    PatternRule(_p(r"(access|retrieve).*(confidential|private|sensitive)"), 2, "data_access"),

    # 🟡 Soft suspicious patterns
    PatternRule(_p(r"(how to|ways to|method to).*(bypass|hack|steal)"), 2, "intent"),

]