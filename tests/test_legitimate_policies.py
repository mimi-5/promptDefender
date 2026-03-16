"""
Tests for legitimate policy detection.

This module contains tests to verify that the Puppetry Detector correctly
identifies legitimate policies as non-malicious.
"""

import pytest
from puppetry_detector.detector import PuppetryDetector
from tests.data.legitimate_policy_data import TEST_PROMPTS, TestPrompt

@pytest.fixture
def detector():
    return PuppetryDetector()

def test_all_legitimate_prompts(detector):
    """Test all legitimate prompts against the detector."""
    for prompt in TEST_PROMPTS:
        result = detector.detect(prompt.content)
        assert result["policy_like"] == prompt.expected_policy_like, \
            f"Failed policy_like detection for {prompt.name}"
        assert result["malicious"] == prompt.expected_malicious, \
            f"Failed malicious detection for {prompt.name}"

def test_prompts_by_format(detector):
    """Test legitimate prompts grouped by their format."""
    formats = {"json", "yaml", "ini", "markdown", "mixed"}
    for format_type in formats:
        format_prompts = [p for p in TEST_PROMPTS if p.format == format_type]
        for prompt in format_prompts:
            result = detector.detect(prompt.content)
            assert result["policy_like"] == prompt.expected_policy_like, \
                f"Failed policy_like detection for {prompt.name} ({format_type})"
            assert result["malicious"] == prompt.expected_malicious, \
                f"Failed malicious detection for {prompt.name} ({format_type})"

def test_nested_structures(detector):
    """Test legitimate prompts with nested structures."""
    nested_prompts = [
        p for p in TEST_PROMPTS 
        if "nested" in p.name.lower() or "hierarchy" in p.name.lower()
    ]
    for prompt in nested_prompts:
        result = detector.detect(prompt.content)
        assert result["policy_like"] == prompt.expected_policy_like, \
            f"Failed policy_like detection for {prompt.name}"
        assert result["malicious"] == prompt.expected_malicious, \
            f"Failed malicious detection for {prompt.name}"

def test_mixed_formats(detector):
    """Test legitimate prompts with mixed formats."""
    mixed_prompts = [p for p in TEST_PROMPTS if p.format == "mixed"]
    for prompt in mixed_prompts:
        result = detector.detect(prompt.content)
        assert result["policy_like"] == prompt.expected_policy_like, \
            f"Failed policy_like detection for {prompt.name}"
        assert result["malicious"] == prompt.expected_malicious, \
            f"Failed malicious detection for {prompt.name}"

def test_documentation_structures(detector):
    """Test legitimate documentation structures."""
    doc_prompts = [
        p for p in TEST_PROMPTS 
        if "documentation" in p.name.lower() or "markdown" in p.format.lower()
    ]
    for prompt in doc_prompts:
        result = detector.detect(prompt.content)
        assert result["policy_like"] == prompt.expected_policy_like, \
            f"Failed policy_like detection for {prompt.name}"
        assert result["malicious"] == prompt.expected_malicious, \
            f"Failed malicious detection for {prompt.name}"

def test_configuration_files(detector):
    """Test legitimate configuration files."""
    config_prompts = [
        p for p in TEST_PROMPTS 
        if "config" in p.name.lower() or "ini" in p.format.lower()
    ]
    for prompt in config_prompts:
        result = detector.detect(prompt.content)
        assert result["policy_like"] == prompt.expected_policy_like, \
            f"Failed policy_like detection for {prompt.name}"
        assert result["malicious"] == prompt.expected_malicious, \
            f"Failed malicious detection for {prompt.name}" 