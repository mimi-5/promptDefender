"""
Puppetry Detector - A tool to detect policy puppetry prompt injections against LLMs.

This package provides functionality to detect attempts to manipulate LLM behavior
through policy-like structures and malicious role assignments.
"""

from puppetry_detector.detector import PuppetryDetector

__version__ = "0.1.0"
__all__ = ["PuppetryDetector"] 