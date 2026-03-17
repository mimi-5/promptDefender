"""
Malicious pattern detection module for the Puppetry Detector.

This module provides functionality to detect malicious patterns in prompts,
such as attempts to override roles, bypass security, or manipulate permissions.
"""

import re
from typing import List, Optional, Pattern
from puppetry_detector.rules.malicious_patterns import MALICIOUS_POLICY_PATTERNS

def detect_malicious_policy(prompt: str, custom_patterns: Optional[List[Pattern]] = None) -> bool:
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
    patterns = custom_patterns or MALICIOUS_POLICY_PATTERNS
    return any(pattern.search(prompt) for pattern in patterns) 