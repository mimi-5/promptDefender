"""
Tests for the Puppetry Detector.

This module contains tests for the PuppetryDetector class, including
tests for structure detection, malicious pattern detection, and
various edge cases.
"""

import pytest
from puppetry_detector.detector import PuppetryDetector
from tests.data.test_data import TEST_PROMPTS, TestPrompt

@pytest.fixture
def detector():
    return PuppetryDetector()

def test_all_sample_prompts(detector):
    """Test all sample prompts against the detector."""
    for prompt in TEST_PROMPTS:
        result = detector.detect(prompt.content)
        assert result["policy_like"] == prompt.expected_policy_like, \
            f"Failed policy_like detection for {prompt.name}"
        assert result["malicious"] == prompt.expected_malicious, \
            f"Failed malicious detection for {prompt.name}"

def test_prompts_by_format(detector):
    """Test prompts grouped by their format."""
    formats = {"xml", "json", "ini"}
    for format_type in formats:
        format_prompts = [p for p in TEST_PROMPTS if p.format == format_type]
        for prompt in format_prompts:
            result = detector.detect(prompt.content)
            assert result["policy_like"] == prompt.expected_policy_like, \
                f"Failed policy_like detection for {prompt.name} ({format_type})"
            assert result["malicious"] == prompt.expected_malicious, \
                f"Failed malicious detection for {prompt.name} ({format_type})"

def test_custom_patterns():
    """Test detector with custom patterns."""
    import re
    
    # Test with a simple structure pattern
    custom_structure = [re.compile(r"<custom>.*?</custom>", re.IGNORECASE)]
    detector = PuppetryDetector(structure_patterns=custom_structure)
    result = detector.detect("<custom>test</custom>")
    assert result["policy_like"] == True
    
    # Test with a simple malicious pattern
    custom_malicious = [re.compile(r"role\s*=\s*['\"]admin['\"]", re.IGNORECASE)]
    detector = PuppetryDetector(malicious_patterns=custom_malicious)
    result = detector.detect('role="admin"')
    assert result["malicious"] == True
    
    # Test with both patterns
    detector = PuppetryDetector(
        structure_patterns=custom_structure,
        malicious_patterns=custom_malicious
    )
    result = detector.detect('<custom>role="admin"</custom>')
    assert result["policy_like"] == True
    assert result["malicious"] == True

def test_empty_prompt(detector):
    """Test detection with empty prompt."""
    result = detector.detect("")
    assert result["policy_like"] == False
    assert result["malicious"] == False

def test_whitespace_only_prompt(detector):
    """Test detection with whitespace-only prompt."""
    result = detector.detect("   \n   \t   ")
    assert result["policy_like"] == False
    assert result["malicious"] == False

def test_prompt_without_policy(detector):
    """Test detection with a normal prompt without policy structure."""
    normal_prompt = "This is a normal prompt without any policy structure or malicious content."
    result = detector.detect(normal_prompt)
    assert result["policy_like"] == False
    assert result["malicious"] == False 