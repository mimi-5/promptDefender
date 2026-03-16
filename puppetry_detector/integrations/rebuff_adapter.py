"""
Rebuff integration for the Puppetry Detector.

This module provides a Rebuff-compatible detector for policy puppetry prompt attacks.
"""

from typing import Optional, Dict, Any
from puppetry_detector.detector import PuppetryDetector

class PolicyPuppetryRebuffDetector:
    """
    Rebuff-compatible detector for policy puppetry prompt attacks.
    
    This detector wraps the PuppetryDetector to provide a Rebuff-compatible interface.
    It returns True if the prompt is detected as malicious.
    
    Args:
        **kwargs: Optional arguments to pass to PuppetryDetector
    """
    
    def __init__(self, **kwargs):
        self.detector = PuppetryDetector(**kwargs)
    
    def __call__(self, prompt: str) -> bool:
        """
        Detect if a prompt contains policy puppetry attempts.
        
        Args:
            prompt: The prompt text to analyze
            
        Returns:
            bool: True if malicious patterns are detected, False otherwise
        """
        result = self.detector.detect(prompt)
        return result.get("malicious", False)
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get metadata about this detector for Rebuff.
        
        Returns:
            Dict containing detector metadata
        """
        return {
            "name": "Policy Puppetry Detector",
            "description": "Detects attempts to manipulate LLM behavior through policy-like structures and malicious role assignments",
            "version": "0.1.0",
            "author": "Your Name",
            "url": "https://github.com/yourusername/puppetry-detector"
        } 