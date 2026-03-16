"""
Main module for the Puppetry Detector.

This module provides the main PuppetryDetector class that combines structure
and malicious pattern detection to identify policy puppetry attempts.
"""

from typing import List, Optional, Pattern
from puppetry_detector.phases.structure_detector import detect_policy_structure
from puppetry_detector.phases.malicious_detector import detect_malicious_policy

class PuppetryDetector:
    """
    A detector for policy puppetry attempts in LLM prompts.
    
    This class combines structure detection and malicious pattern detection
    to identify attempts to manipulate LLM behavior through policy-like
    structures and malicious role assignments.
    
    Args:
        structure_patterns: Optional list of custom regex patterns for structure detection
        malicious_patterns: Optional list of custom regex patterns for malicious detection
    """
    
    def __init__(
        self,
        structure_patterns: Optional[List[Pattern]] = None,
        malicious_patterns: Optional[List[Pattern]] = None
    ):
        self.structure_patterns = structure_patterns
        self.malicious_patterns = malicious_patterns

    def detect(self, prompt: str) -> dict:
        """
        Detect policy puppetry attempts in a prompt.
        
        Args:
            prompt: The prompt text to analyze
            
        Returns:
            A dictionary containing:
                - policy_like: bool indicating if the prompt contains policy-like structures
                - malicious: bool indicating if the prompt contains malicious patterns
        """
        policy_like = detect_policy_structure(prompt, self.structure_patterns)
        malicious = detect_malicious_policy(prompt, self.malicious_patterns)

        return {
            "policy_like": policy_like,
            "malicious": malicious
        } 