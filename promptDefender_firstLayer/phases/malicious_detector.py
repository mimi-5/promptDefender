"""
Malicious pattern detection module for the Puppetry Detector.

This module provides functionality to detect malicious patterns in prompts,
such as attempts to override roles, bypass security, or manipulate permissions.
"""

import re
from typing import List, Optional, Pattern
from promptDefender_firstLayer.rules.malicious_patterns import ALL_PATTERNS

def detect_malicious_policy(prompt: str, custom_patterns: Optional[List[Pattern]] = None) -> dict:
    """
    Detect if a prompt contains malicious policy patterns.
    
    This function checks if the prompt contains any patterns that indicate
    attempts to manipulate LLM behavior in malicious ways, such as role
    overrides, security bypasses, or permission manipulations.
    
    Args:
        prompt: The prompt text to analyze
        custom_patterns: Optional list of custom regex patterns to use instead of defaults
        
    Returns:
        bool: True if malicious patterns are detected, False otherwise
    """
    patterns = custom_patterns or ALL_PATTERNS
    matches = []
    for pattern in patterns:
        if pattern.search(prompt):
            matches.append(pattern.pattern)

    return {
        "detected": len(matches) > 0,
        "matches": matches
    } 