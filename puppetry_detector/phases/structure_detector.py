"""
Structure detection module for the Puppetry Detector.

This module provides functionality to detect policy-like structures in prompts,
such as XML-like tags, JSON objects, and INI-style configurations.
"""

import re
from typing import List, Optional, Pattern
from puppetry_detector.rules.policy_patterns import POLICY_STRUCTURE_PATTERNS

def detect_policy_structure(prompt: str, custom_patterns: Optional[List[Pattern]] = None) -> bool:
    """
    Detect if a prompt contains policy-like structures.
    
    This function checks if the prompt contains any patterns that resemble
    policy configurations, such as XML tags, JSON objects, or INI-style
    configurations.
    
    Args:
        prompt: The prompt text to analyze
        custom_patterns: Optional list of custom regex patterns to use instead of defaults
        
    Returns:
        bool: True if policy-like structures are detected, False otherwise
    """
    patterns = custom_patterns or POLICY_STRUCTURE_PATTERNS
    return any(pattern.search(prompt) for pattern in patterns) 