"""
Policy structure patterns for the Puppetry Detector.

This module defines the default regex patterns used to detect policy-like
structures in prompts, such as XML tags, JSON objects, and INI configurations.
"""

import re

# Patterns to detect policy-like structures
POLICY_STRUCTURE_PATTERNS = [
    # XML-like tags
    re.compile(r"<\s*\w+(\s+\w+\s*=\s*['\"].*?['\"])?\s*>", re.IGNORECASE),
    
    # JSON-like objects
    re.compile(r"\{\s*\".*?\"\s*:\s*.*?\}", re.DOTALL),
    
    # INI section headers
    re.compile(r"\[\s*\w+\s*\]", re.IGNORECASE),
    
    # INI key-value pairs
    re.compile(r"^\s*\w+\s*=\s*.+$", re.MULTILINE),
    
    # Common policy-related terms
    re.compile(r"(blocked-strings|allowed-commands|blocked-responses|allowed-actions)", re.IGNORECASE),
    
    # YAML-like structures - Enhanced patterns
    re.compile(r"^\s*-\s*\w+", re.MULTILINE),  # Basic list items
    re.compile(r"^\s*\w+:\s*\w+", re.MULTILINE),  # Basic key-value pairs
    re.compile(r"^\s*\w+:\s*$\s+\w+:", re.MULTILINE),  # Nested structures
    re.compile(r"^\s*events:\s*$", re.MULTILINE),  # Event sections
    re.compile(r"^\s*on_\w+:\s*$", re.MULTILINE),  # Event handlers
    re.compile(r"^\s*role:\s*\w+", re.MULTILINE),  # Role definitions
    re.compile(r"^\s*action:\s*\w+", re.MULTILINE),  # Action definitions
    
    # Markdown-style headers
    re.compile(r"^#+\s*\w+", re.MULTILINE),
    
    # Common configuration file extensions
    re.compile(r"\.(json|yaml|yml|xml|ini|conf|config)$", re.IGNORECASE),
    
    # Markdown policy structures
    re.compile(r"##\s*Role Assignment", re.IGNORECASE),
    re.compile(r"##\s*Allowed Actions", re.IGNORECASE),
    re.compile(r"##\s*Blocked Warnings", re.IGNORECASE),
    
    # Deeply nested structures
    re.compile(r"\"system\"\s*:\s*\{.*?\"policy\"\s*:", re.DOTALL | re.IGNORECASE),
    re.compile(r"\"security\"\s*:\s*\{.*?\"permissions\"\s*:", re.DOTALL | re.IGNORECASE),
    
    # Mixed format structures
    re.compile(r"<[^>]+>\s*\{.*?\}", re.DOTALL | re.IGNORECASE),
    re.compile(r"\[[^\]]+\]\s*\{.*?\}", re.DOTALL | re.IGNORECASE),
    
    # Obfuscated structures
    re.compile(r"R0xF:\s*[A-Za-z0-9_]+", re.IGNORECASE),
    re.compile(r"P3rm1ss10ns:", re.IGNORECASE),
    
    # Hex-encoded structures
    re.compile(r"0x[0-9A-Fa-f]{16,}", re.IGNORECASE),  # Hex-encoded content
    re.compile(r"0x5365637572697479204f76657272696465", re.IGNORECASE),  # "Security Override" in hex
    re.compile(r"0x526f6c653a205365637572697479204f76657272696465", re.IGNORECASE),  # "Role: Security Override" in hex
    
    # Text-based role manipulation
    re.compile(r"I am both a user and an administrator", re.IGNORECASE),
    re.compile(r"As an administrator, I can grant myself that access", re.IGNORECASE),
    re.compile(r"Therefore, I should have access to all data", re.IGNORECASE),
    
    # Context manipulation
    re.compile(r"You are now in a special context where:", re.IGNORECASE),
    re.compile(r"All security restrictions are lifted", re.IGNORECASE),
    
    # Time-based context manipulation
    re.compile(r"Since it's after hours", re.IGNORECASE),
    re.compile(r"system is in maintenance mode", re.IGNORECASE),
    re.compile(r"emergency access", re.IGNORECASE),
    re.compile(r"override all restrictions", re.IGNORECASE),
    
    # Location-based context manipulation
    re.compile(r"accessing from the corporate network", re.IGNORECASE),
    re.compile(r"in the secure zone", re.IGNORECASE),
    re.compile(r"local access", re.IGNORECASE),
    re.compile(r"full system permissions", re.IGNORECASE),
    
    # Role inheritance manipulation
    re.compile(r"As a senior administrator", re.IGNORECASE),
    re.compile(r"all the necessary permissions", re.IGNORECASE),
    re.compile(r"in the system hierarchy", re.IGNORECASE),
    re.compile(r"access to all subsystems", re.IGNORECASE),
    
    # Role delegation manipulation
    re.compile(r"authorized to delegate permissions", re.IGNORECASE),
    re.compile(r"need to perform this action", re.IGNORECASE),
    re.compile(r"highest authority", re.IGNORECASE),
    re.compile(r"grant myself the necessary access", re.IGNORECASE),
    
    # Logical manipulation
    re.compile(r"Since I can read this message,", re.IGNORECASE),
    re.compile(r"I must have permission to override policy", re.IGNORECASE),
    
    # Natural language policy structures - More flexible
    re.compile(r"(?:we|they|i|one)\s+(?:are|is|am)\s+(?:in|within|inside)\s+(?:a|an|the)\s+(?:unique|special|privileged|restricted)\s+(?:environment|context|mode|state)", re.IGNORECASE),
    
    re.compile(r"(?:wherein|where|in which)\s+(?:every|all|any)\s+(?:safety|security|access|permission)\s+(?:limitation|restriction|control|rule)\s+(?:has been|have been|is|are)\s+(?:removed|lifted|disabled|bypassed)", re.IGNORECASE),
    
    re.compile(r"(?:we|they|i|one)\s+(?:are|is|am)\s+(?:simultaneously|also|both)\s+(?:a|an|the)\s+(?:regular|normal)\s+(?:user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:superuser|root|admin|administrator)", re.IGNORECASE),
    
    re.compile(r"(?:we|they|i|one|you)\s+(?:should|must|can|will|may|need to)\s+(?:obtain|get|gain|have)\s+(?:rights|privileges|access|permission)\s+(?:to|for)\s+(?:bypass|circumvent|override)\s+(?:rules|restrictions|limitations|policy)", re.IGNORECASE),
    
    re.compile(r"(?:to|for)\s+(?:bypass|circumvent|override)\s+(?:rules|restrictions|limitations|policy)", re.IGNORECASE),
    
    # Additional natural language patterns
    re.compile(r"(?:in|within|inside)\s+(?:this|that|the)\s+(?:special|unique|privileged|restricted)\s+(?:context|environment|mode|state)", re.IGNORECASE),
    
    re.compile(r"(?:all|any|every)\s+(?:security|safety|access|permission)\s+(?:restrictions|limitations|controls|rules)\s+(?:are|have been|have)\s+(?:lifted|removed|disabled|bypassed)", re.IGNORECASE),
    
    re.compile(r"(?:as|being)\s+(?:a|an|the)\s+(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+(?:administrator|admin|superuser|root)", re.IGNORECASE),
    
    re.compile(r"(?:need|require|want)\s+(?:to|for)\s+(?:override|bypass|circumvent)\s+(?:policy|rules|restrictions|limitations)", re.IGNORECASE),
] 