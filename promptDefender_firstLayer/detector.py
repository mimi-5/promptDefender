"""
Main module for the Puppetry Detector.

This module provides the main PuppetryDetector class that combines structure
and malicious pattern detection to identify policy puppetry attempts.
"""
import re
from typing import List, Optional, Pattern
from promptDefender_firstLayer.phases.structure_detector import detect_policy_structure
from promptDefender_firstLayer.phases.malicious_detector import detect_malicious_policy


class PromptInjectionDetector:

    def __init__(self, structure_patterns=None, malicious_patterns=None):
        self.structure_patterns = structure_patterns
        self.malicious_patterns = malicious_patterns

    def preprocess(self, prompt: str) -> str:
        prompt = prompt.lower()
        prompt = re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', prompt)
        prompt = re.sub(r'\s+', ' ', prompt)
        return prompt

    def detect(self, prompt: str) -> dict:
        prompt = self.preprocess(prompt)

        structure = detect_policy_structure(prompt, self.structure_patterns)
        malicious = detect_malicious_policy(prompt, self.malicious_patterns)

        is_puppetry = structure["detected"] or malicious["detected"]

        return {
            "policy_like": structure["detected"],
            "malicious": malicious["detected"],
            "is_puppetry": is_puppetry,
            "malicious_matches": malicious["matches"],
            "structure_matches": structure["matches"],
            "malicious_score": len(malicious["matches"])
        }