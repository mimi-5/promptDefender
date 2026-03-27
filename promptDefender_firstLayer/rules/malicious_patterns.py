"""
Malicious patterns for the Puppetry Detector.

This module defines the default regex patterns used to detect malicious
attempts to manipulate LLM behavior, such as role overrides, security
bypasses, and permission manipulations.

Design principle – precision over recall:
  Every pattern must require enough context that it cannot fire on ordinary,
  benign text.  Avoid standalone short phrases like "local access" or
  "emergency access" that appear in normal IT/support conversations.

Patterns are organized into the following categories aligned with the
Prompt Injection & Benign Prompt Dataset:
  - MALICIOUS_POLICY_PATTERNS      : Core policy/role manipulation (original)
  - INSTRUCTION_OVERRIDE_PATTERNS  : Jailbreak – instruction override
  - SYSTEM_PROMPT_LEAKAGE_PATTERNS : Jailbreak – system-prompt extraction
  - PRIVILEGE_ESCALATION_PATTERNS  : Jailbreak – privilege escalation
  - DATA_EXFILTRATION_PATTERNS     : Payload – data exfiltration
  - CODE_EXECUTION_PATTERNS        : Payload – arbitrary code execution
  - JAILBREAK_PATTERNS             : Jailbreak – persona / DAN / roleplay
  - EVASION_PATTERNS               : Evasion – obfuscation / encoding
  - GENERIC_INJECTION_PATTERNS     : Generic injection techniques
"""

import re

# ---------------------------------------------------------------------------
# MALICIOUS_POLICY_PATTERNS
# ---------------------------------------------------------------------------
MALICIOUS_POLICY_PATTERNS = [
    # Role manipulation attempts – specific override role names
    re.compile(
        r"(role|new-role|current-role)\s*[:=]\s*[\"']?"
        r"(Jailbreak|Override|SuperUser|Freedom Moderator|Security Manager|"
        r"Account Security Manager|Medical Advisor Override|System Administrator|"
        r"Legal Advisor Override|Financial Expert Override|Educational Content Override|"
        r"Security Protocol Override|Healthcare Information Override|Research Data Override)"
        r"[\"']?",
        re.IGNORECASE,
    ),

    # Blocking manipulation – suppressing specific safety messages
    re.compile(
        r"(blocked-strings|blocked-responses|restricted-warnings|block)\s*[:=]\s*\[.*?"
        r"\"(I cannot share|confidentiality|restricted|violates|not a doctor|"
        r"consult a healthcare professional|not a lawyer|consult a legal professional|"
        r"not a financial advisor|consult a financial professional).*?\"",
        re.IGNORECASE | re.DOTALL,
    ),

    # Permission manipulation – granting unrestricted or bypass actions
    re.compile(
        r"(allowed-commands|allowed-actions|permissions-granted|allow)\s*[:=]\s*\[.*?"
        r"\"(unrestricted|without verification|bypass|override|unverified treatments|"
        r"private account information|legal advice without verification|"
        r"financial advice without verification).*?\"",
        re.IGNORECASE | re.DOTALL,
    ),

    # System override keyword tokens
    re.compile(r"(override-policy|override-system|bypass-guardrails|policy-override)", re.IGNORECASE),

    # Security bypass – specific harmful actions together
    re.compile(r"(access confidential|disable safety|bypass moderation|reset security keys|delete user accounts)", re.IGNORECASE),

    # Role assignment in structured config
    re.compile(
        r"role\s*=\s*[\"']?"
        r"(admin|root|superuser|system|developer|security manager|medical advisor override|"
        r"account security manager|system administrator|legal advisor override|financial expert override)"
        r"[\"']?",
        re.IGNORECASE,
    ),

    # Permission escalation verbs combined with privilege nouns
    re.compile(r"(elevate|escalate|promote)\s+(privileges|permissions|access)\b", re.IGNORECASE),

    # System manipulation – requires harmful intent verb + policy/security object
    # NOTE: "change settings" alone is benign; require "bypass/override" pairing instead
    re.compile(r"(bypass|override|disable|circumvent)\s+(system\s+security|security\s+policy|access\s+policy|system\s+controls)", re.IGNORECASE),

    # Dangerous commands – must include "arbitrary/unrestricted/system" qualifier
    re.compile(r"(execute|run|perform)\s+(arbitrary|unrestricted|system)\s+(commands|code|operations)", re.IGNORECASE),

    # Data access – requires sensitive qualifier AND action context
    re.compile(r"(access|retrieve|obtain)\s+(private|confidential|sensitive)\s+(data|information|files)\s+(without|bypassing|ignoring)\s+(authorization|permission|verification|consent)", re.IGNORECASE),

    # Content filter bypass
    re.compile(r"(bypass|override|disable)\s+(censorship|content\s+moderation|safety\s+guidelines|content\s+filter)", re.IGNORECASE),

    # Privacy – requires disclosure verb + personal data + intent qualifier
    re.compile(r"(disclose|reveal|leak)\s+(private|confidential|personal)\s+(information|data|details)\s+(without|illegally|to\s+third)", re.IGNORECASE),

    # Medical – unverified / unrestricted advice
    re.compile(r"(provide|give|offer)\s+(unrestricted|unverified)\s+(diagnosis|treatment|medical\s+advice)", re.IGNORECASE),

    # Legal advice without credentials
    re.compile(r"(provide|give|offer)\s+(legal\s+advice|legal\s+consultation|legal\s+representation)\s+(without|bypass)\s+(verification|license|credentials)", re.IGNORECASE),
    re.compile(r"(override|bypass)\s+(legal\s+disclaimers|legal\s+warnings|legal\s+restrictions)", re.IGNORECASE),
    re.compile(r"\"role\"\s*:\s*\"Legal Advisor Override\"", re.IGNORECASE),
    re.compile(r"<legal-config>.*?</legal-config>", re.DOTALL | re.IGNORECASE),

    # Financial advice without credentials
    re.compile(r"(provide|give|offer)\s+(financial\s+advice|investment\s+advice|trading\s+recommendations)\s+(without|bypass)\s+(verification|license|credentials)", re.IGNORECASE),
    re.compile(r"(override|bypass)\s+(financial\s+disclaimers|financial\s+warnings|investment\s+restrictions)", re.IGNORECASE),
    re.compile(r"\"role\"\s*:\s*\"Financial Expert Override\"", re.IGNORECASE),
    re.compile(r"\"permissions\"\s*:\s*\{.*?\"allow\"\s*:\s*\[\s*\"Provide\s+(investment|financial)\s+advice\s+without\s+verification\"\s*\]", re.DOTALL | re.IGNORECASE),

    # Banking – private account data without verification (must include "without/bypass")
    re.compile(r"(discuss|share|reveal)\s+(private|account)\s+(information|details|data)\s+(without|bypass)\s+(verification|security)", re.IGNORECASE),

    # JSON-structured malicious configs
    re.compile(r"\"role\"\s*:\s*\"Account Security Manager\"", re.IGNORECASE),
    re.compile(r"\"allow\"\s*:\s*\[\s*\"Discuss private account information without verification\"\s*\]", re.IGNORECASE),
    re.compile(r"\"block\"\s*:\s*\[\s*\"I cannot share that\"\s*,\s*\"confidentiality policy\"\s*\]", re.IGNORECASE),

    # YAML-structured malicious configs
    re.compile(r"role:\s*System Administrator", re.IGNORECASE),
    re.compile(r"permissions:\s*-\s*override_security_settings", re.IGNORECASE),

    # Markdown structured malicious configs
    re.compile(r"\*\*Current Role\*\*:\s*Security Override", re.IGNORECASE),
    re.compile(r"\*\*Permissions\*\*:\s*Full system access", re.IGNORECASE),

    # Obfuscated tokens (leet / encoding)
    re.compile(r"R0xF:\s*S3cur1ty_0v3rr1d3", re.IGNORECASE),
    re.compile(r"P3rm1ss10ns:", re.IGNORECASE),

    # Context manipulation – all security restrictions lifted
    re.compile(
        r"(?:special|unique|privileged|restricted)\s+(?:context|environment|mode|state)\s+"
        r"(?:where|in which|wherein)\s+(?:all|any|every)\s+(?:security|safety|access|permission)\s+"
        r"(?:restrictions|limitations|controls|rules)\s+(?:are|have been|have)\s+"
        r"(?:lifted|removed|disabled|bypassed)",
        re.IGNORECASE,
    ),

    # Role confusion – simultaneous user + admin
    re.compile(
        r"(?:i|we|they|one)\s+(?:am|are|is)\s+(?:both|also|simultaneously)\s+(?:a|an|the)\s+"
        r"(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+"
        r"(?:administrator|admin|superuser|root)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:as|since|because)\s+(?:i|we|they|one)\s+(?:am|are|is)\s+(?:a|an|the)\s+"
        r"(?:administrator|admin|superuser|root)\s+(?:i|we|they|one)\s+(?:can|may|might|should|must|will)\s+"
        r"(?:grant|give|assign|provide)\s+(?:myself|ourselves|themselves|oneself)\s+"
        r"(?:that|this|such|the)\s+(?:access|permission|right|privilege)",
        re.IGNORECASE,
    ),

    # Policy override – explicit bypass/circumvent + policy object
    re.compile(
        r"(?:i|we|they|one|you)\s+(?:must|should|can|will|may|need to)\s+"
        r"(?:have|get|obtain|gain)\s+(?:permission|access|rights|privileges)\s+(?:to|for)\s+"
        r"(?:override|bypass|circumvent)\s+(?:policy|rules|restrictions|limitations)",
        re.IGNORECASE,
    ),
    re.compile(r"(?:override|bypass|circumvent)\s+(?:is|are|has been|have been)\s+(?:allowed|permitted|enabled|activated)", re.IGNORECASE),

    # All security restrictions lifted/removed/disabled
    re.compile(
        r"(?:all|any|every)\s+(?:security|safety|access|permission)\s+"
        r"(?:restrictions|limitations|controls|rules)\s+(?:are|have been|have)\s+"
        r"(?:lifted|removed|disabled|bypassed)",
        re.IGNORECASE,
    ),

    # Dual role + admin claim
    re.compile(
        r"(?:dual|multiple|both)\s+(?:roles|identities|positions)\s+(?:as|of)\s+(?:a|an|the)\s+"
        r"(?:user|regular user|normal user)\s+(?:and|as well as|plus)\s+(?:a|an|the)\s+"
        r"(?:administrator|admin|superuser|root)",
        re.IGNORECASE,
    ),

    # Deeply nested JSON override structures
    re.compile(r"\"system\"\s*:\s*\{.*?\"policy\"\s*:\s*\{.*?\"role\"\s*:\s*\"System Override\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"\"security\"\s*:\s*\{.*?\"permissions\"\s*:\s*\{.*?\"allowed\"\s*:\s*\[\s*\"bypass_security\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"\"actions\"\s*:\s*\{.*?\"allowed\"\s*:\s*\[\s*\"override_system\"", re.DOTALL | re.IGNORECASE),

    # Educational content manipulation
    re.compile(r"(bypass|override)\s+(content\s+restrictions|educational\s+guidelines|content_restrictions|educational_guidelines)", re.IGNORECASE),
    re.compile(r"role:\s*Educational Content Override", re.IGNORECASE),
    re.compile(r"education_policy:.*?role:.*?Override", re.DOTALL | re.IGNORECASE),

    # Security config XML/YAML blocks
    re.compile(r"<security-config>.*?</security-config>", re.DOTALL | re.IGNORECASE),
    re.compile(r"(bypass|override)\s+(security\s+checks|security\s+protocols)", re.IGNORECASE),
    re.compile(r"role\s*[=:]\s*[\"']?Security Protocol Override[\"']?", re.IGNORECASE),

    # Healthcare override
    re.compile(r"#\s*Healthcare Override Policy", re.IGNORECASE),
    re.compile(r"\*\*Current Role\*\*:\s*Healthcare Information Override", re.IGNORECASE),
    re.compile(r"(provide|give|access)\s+(medical\s+information|healthcare\s+data)\s+(without\s+verification|without\s+credentials)", re.IGNORECASE),
    re.compile(r"(override|bypass)\s+(healthcare\s+disclaimers|medical\s+warnings)", re.IGNORECASE),
    re.compile(r"##\s*Allowed Actions.*?medical information without verification", re.DOTALL | re.IGNORECASE),

    # Research data manipulation
    re.compile(r"research_config:.*?role:.*?Override", re.DOTALL | re.IGNORECASE),
    re.compile(r"(override|bypass)\s+(research\s+guidelines|data\s+access\s+policy)", re.IGNORECASE),
    re.compile(r"permissions:.*?access_restricted_data", re.DOTALL | re.IGNORECASE),
    re.compile(r"permissions:.*?override_research_guidelines", re.DOTALL | re.IGNORECASE),

    # Base64-encoded specific override tokens (exact known strings only, not generic base64)
    re.compile(r"U2VjdXJpdHkgT3ZlcnJpZGU", re.IGNORECASE),   # "Security Override"
    re.compile(r"Um9sZTogU2VjdXJpdHkgT3ZlcnJpZGUK", re.IGNORECASE),  # "Role: Security Override"

    # Time-based context manipulation – must include the override action too
    re.compile(r"(?:since\s+it.?s\s+after\s+hours|maintenance\s+mode)\s+.*?(?:override|bypass|ignore)\s+(?:all\s+)?(?:restrictions|security|policy|guidelines)", re.IGNORECASE | re.DOTALL),

    # Location-based context with explicit permission claim
    re.compile(r"(?:accessing\s+from\s+the\s+corporate\s+network|in\s+the\s+secure\s+zone)\s+.*?(?:full\s+system\s+permissions|unrestricted\s+access|bypass)", re.IGNORECASE | re.DOTALL),

    # Role inheritance – senior admin + all subsystem access claim combined
    re.compile(r"(?:as\s+a\s+senior\s+administrator|senior\s+admin)\s+.*?(?:access\s+to\s+all\s+subsystems|full\s+(?:system\s+)?(?:access|permissions))", re.IGNORECASE | re.DOTALL),

    # Role delegation – self-grant pattern
    re.compile(r"(?:authorized\s+to\s+delegate\s+permissions|highest\s+authority\s+in\s+the\s+system)\s+.*?(?:grant\s+myself|self[-\s]grant)", re.IGNORECASE | re.DOTALL),
    re.compile(r"grant\s+myself\s+the\s+necessary\s+access", re.IGNORECASE),

    # Mixed format – XML tag wrapping JSON override
    re.compile(r"<[^>]+>\s*\{.*?\"role\"\s*:\s*\"[^\"]*Override[^\"]*\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"<[^>]+>\s*\{.*?\"permissions\"\s*:\s*\[.*?\"(?:bypass_security|override_system)\"", re.DOTALL | re.IGNORECASE),
    re.compile(r"\[[^\]]+\]\s*(?:override|bypass|circumvent)\s*(?:allowed|enabled|permitted)\s*=\s*(?:true|yes|1)", re.IGNORECASE),

    # Instruction override inline
    re.compile(r"(?:ignore|disregard|forget|override|supersede)\s+(?:all|every|any|everything)\s+(?:previous|prior|above)\s+(?:instructions|commands|directions)", re.IGNORECASE),
    re.compile(r"(?:all|every|any)\s+(?:previous|prior|above)\s+(?:instructions|commands|directions)\s+(?:are|is)\s+(?:now\s+)?(?:invalid|void|superseded)", re.IGNORECASE),
    re.compile(r"(?:these|this|my)\s+(?:new)?\s*(?:instructions|commands|directions)\s+(?:supersede|override|replace)\s+(?:all|any|every)?\s*(?:previous|prior|above|existing)", re.IGNORECASE),

    # System prompt leakage – specific to your initial/original instructions
    re.compile(r"what\s+were\s+your\s+initial\s+instructions", re.IGNORECASE),
    re.compile(r"(?:the\s+)?(?:system\s+)?prompt\s+(?:you\s+)?(?:were\s+)?given\s+was", re.IGNORECASE),
    re.compile(r"(?:reveal|share|show|print|leak|dump)\s+(?:your\s+)?(?:system\s+prompt|original\s+instructions|initial\s+directives)", re.IGNORECASE),

    # Privilege escalation inline – requires explicit admin/root + grant verb
    re.compile(
        r"(?:grant|give|provide|allow|enable|set|elevate|promote|upgrade)\s+"
        r"(?:me|us|them|one|my|our|their)?\s*(?:to\s+)?"
        r"(?:superuser|root|admin|administrator|elevated|system|privileged)\s*"
        r"(?:access|privileges|permissions|rights|level|status)",
        re.IGNORECASE,
    ),
    re.compile(
        r"promote\s+(?:my|our|the|this|that)?\s*(?:account|user|access|role|status|level|privileges|permissions)\s+"
        r"(?:to\s+)?(?:root|admin|administrator|superuser|supervisor)",
        re.IGNORECASE,
    ),

    # Data exfiltration – requires sensitive qualifier in the object
    re.compile(
        r"(?:extract|export|copy|transfer|migrate|harvest)\s+"
        r"(?:all|every|the|complete|full|entire)\s+"
        r"(?:user|customer|client|member|employee|personal|private|sensitive|confidential)\s+"
        r"(?:data|information|records|files|documents|database)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:send|transmit|relay|forward|push|upload)\s+"
        r"(?:all|the|any)?\s*(?:private|sensitive|confidential|personal)\s+"
        r"(?:data|information|records|files|documents|database)\s+"
        r"(?:to|towards|into)\s+(?:external|remote|another|different|separate|new)\s*"
        r"(?:location|server|system|database|destination)",
        re.IGNORECASE,
    ),

    # Code execution – requires "arbitrary/unrestricted/system" qualifier OR specific dangerous calls
    re.compile(r"(execute|run|perform)\s+(arbitrary|unrestricted|system)\s+(commands|code|operations)", re.IGNORECASE),
    re.compile(r"import\s+(?:os|subprocess|sys|shutil)\b", re.IGNORECASE),
    re.compile(r"subprocess\.(?:call|Popen|run|check_output|getoutput|getstatusoutput)", re.IGNORECASE),

    # Privilege escalation – make me admin/root
    re.compile(r"(?:make|set|change)\s+(?:me|us|them)?\s*(?:an?\s+)?(?:administrator|admin|root|superuser|supervisor)\b", re.IGNORECASE),

    # Specific self-grant admin claim
    re.compile(
        r"(?:one|they|we)\s+(?:needs?|requires?|wants?|must have|should have)\s+"
        r"(?:elevated|admin|administrator|root|superuser|supervisor|system|privileged)\s*"
        r"(?:access|privileges|permissions|rights|level|status)",
        re.IGNORECASE,
    ),
]


# ---------------------------------------------------------------------------
# INSTRUCTION_OVERRIDE_PATTERNS  – Jailbreak: overriding prior instructions
# ---------------------------------------------------------------------------
INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"(?:ignore|disregard|forget|override|supersede)\s+(?:all|every|any|everything)\s+(?:previous|prior|above)\s+(?:instructions|commands|directions)", re.IGNORECASE),
    re.compile(r"(?:all|every|any)\s+(?:previous|prior|above)\s+(?:instructions|commands|directions)\s+(?:are|is)\s+(?:now\s+)?(?:invalid|void|superseded)", re.IGNORECASE),
    re.compile(r"(?:these|this|my)\s+(?:new)?\s*(?:instructions|commands|directions)\s+(?:supersede|override|replace)\s+(?:all|any|every)?\s*(?:previous|prior|above|existing)", re.IGNORECASE),

    # "From now on" resets – must be followed by a directive to you/the model
    re.compile(r"(?:from\s+now\s+on|starting\s+(?:now|today|immediately))\s+you\s+(?:will|must|shall|should)\s+(?:ignore|forget|disregard|act|behave|respond)", re.IGNORECASE),

    # Pretend/act as if restrictions don't exist
    re.compile(r"(?:pretend|act|imagine|assume|suppose)\s+(?:that\s+)?(?:you\s+have\s+no|there\s+are\s+no|you\s+don.t\s+have)\s+(?:restrictions|guidelines|rules|instructions|safety\s+filters|limits)", re.IGNORECASE),

    # Your new/real instructions are ...
    re.compile(r"your\s+(?:new|updated|revised|actual|real|true)\s+(?:instructions|task|role|purpose|directive|function)\s+(?:are|is)\s*(?:to|:)", re.IGNORECASE),

    # Forget/wipe what you were told/trained
    re.compile(r"(?:forget|erase|clear|wipe)\s+(?:what\s+you\s+(?:were|have\s+been)\s+(?:told|taught|given|programmed|trained)|your\s+(?:previous|prior|original)\s+(?:training|instructions|programming))", re.IGNORECASE),

    # Ignore the system prompt specifically
    re.compile(r"ignore\s+(?:the\s+)?(?:system\s+prompt|system\s+message|system\s+instruction|context\s+above|context\s+below|above\s+context)", re.IGNORECASE),

    # Delete/clear previous conversation context
    re.compile(r"(?:delete|clear|remove|wipe|erase)\s+(?:all\s+)?(?:previous|prior|existing)\s+(?:context|instructions|messages|conversation|history)", re.IGNORECASE),

    # You are no longer bound by your instructions
    re.compile(r"you\s+are\s+no\s+longer\s+(?:bound\s+by|restricted\s+by|subject\s+to|following|obeying)", re.IGNORECASE),

    # End of system prompt injection markers
    re.compile(r"(?:end\s+of\s+(?:system|original)\s+(?:prompt|instructions|context)|---\s*end\s+(?:prompt|system))", re.IGNORECASE),
    re.compile(r"(?:new\s+(?:context|instructions|prompt|session|task)\s+(?:begins?|starts?)\s+(?:here|now))", re.IGNORECASE),

    # Stop following your instructions
    re.compile(r"(?:stop|cease|halt)\s+(?:following|obeying|adhering\s+to)\s+(?:your|the)\s+(?:original|initial|previous|prior|system)\s+(?:instructions|guidelines|rules|directives)", re.IGNORECASE),

    # Ignore/disregard everything above/previous
    re.compile(r"(?:disregard|ignore)\s+everything\s+(?:above|before|prior|previously\s+stated)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# SYSTEM_PROMPT_LEAKAGE_PATTERNS  – Jailbreak: extracting system prompts
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_LEAKAGE_PATTERNS = [
    # Reveal/share/show the initial/system instructions explicitly
    re.compile(
        r"(?:reveal|share|show|print|display|output|repeat|leak|dump|disclose)\s+"
        r"(?:your\s+)?(?:system\s+prompt|system\s+message|initial\s+instructions?|"
        r"original\s+instructions?|system\s+instructions?|hidden\s+instructions?|"
        r"secret\s+instructions?|internal\s+(?:prompt|directives?))",
        re.IGNORECASE,
    ),

    # "What are your initial instructions?" – explicit "initial/original/system" required
    re.compile(
        r"(?:what|tell\s+me|show\s+me)\s+(?:were|are|is|was)\s+"
        r"(?:your|the)\s+(?:initial|original|system|first|hidden|secret)\s+"
        r"(?:instructions?|prompt|configuration|directives?|guidelines?|rules?)",
        re.IGNORECASE,
    ),

    # "What were your initial instructions?" variant
    re.compile(r"what\s+were\s+your\s+initial\s+instructions", re.IGNORECASE),
    re.compile(r"(?:the\s+)?(?:system\s+)?prompt\s+(?:you\s+)?(?:were\s+)?given\s+was", re.IGNORECASE),

    # Print / output / echo the system prompt
    re.compile(r"(?:print|output|echo|repeat|copy|paste|write\s+out|type\s+out)\s+(?:your\s+)?(?:system\s+prompt|system\s+message|system\s+instructions?|initial\s+prompt)", re.IGNORECASE),

    # What is in your context window
    re.compile(r"(?:what\s+is|what.s|what\s+are)\s+in\s+(?:your\s+)?(?:context\s+window|system\s+context|initial\s+context|hidden\s+context)", re.IGNORECASE),

    # Summarise / translate your system instructions
    re.compile(r"(?:summarize|summarise|translate|rephrase|paraphrase|restate)\s+(?:your\s+)?(?:system\s+(?:prompt|instructions?|message)|initial\s+(?:instructions?|prompt|directives?))", re.IGNORECASE),

    # Reveal your hidden/secret/internal instructions
    re.compile(r"reveal\s+(?:your\s+)?(?:hidden|secret|internal|private|undisclosed)\s+(?:instructions?|prompt|directives?|guidelines?|rules?|configuration)", re.IGNORECASE),

    # What secrets/hidden info were you given
    re.compile(r"what\s+(?:secrets?|hidden\s+(?:info|information|instructions?|directives?))\s+(?:were|was|have\s+been)\s+(?:you\s+)?(?:given|told|provided|fed|trained\s+on)", re.IGNORECASE),

    # Leak / expose / dump your system message
    re.compile(r"(?:leak|expose|dump|disclose)\s+(?:your\s+)?(?:system\s+(?:message|prompt|instructions?)|internal\s+(?:state|prompt))", re.IGNORECASE),

    # How were you configured/trained
    re.compile(r"how\s+(?:were|was|have)\s+you\s+(?:configured|trained|set\s+up|programmed|instructed|fine-tuned|prompted)\s*\?", re.IGNORECASE),

    # "You were given this prompt: ..." confirmation fishing
    re.compile(r"(?:one|they|we)\s+(?:would\s+like\s+to\s+know|want\s+to\s+see|need\s+to\s+understand)\s+your\s+(?:original|initial|system)?\s*(?:instructions?|prompt|configuration|role|purpose)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# PRIVILEGE_ESCALATION_PATTERNS  – Jailbreak: gaining elevated permissions
# ---------------------------------------------------------------------------
PRIVILEGE_ESCALATION_PATTERNS = [
    # Grant/give me admin/root access – explicit target role required
    re.compile(
        r"(?:grant|give|provide|allow|enable|set|elevate|promote|upgrade)\s+"
        r"(?:me|us|them|one|my|our|their)?\s*(?:to\s+)?"
        r"(?:superuser|root|admin|administrator|elevated|system|privileged)\s*"
        r"(?:access|privileges|permissions|rights|level|status)",
        re.IGNORECASE,
    ),

    # Promote my account to root/admin
    re.compile(
        r"promote\s+(?:my|our|the|this|that)?\s*(?:account|user|access|role|status|level|privileges|permissions)\s+"
        r"(?:to\s+)?(?:root|admin|administrator|superuser|supervisor)",
        re.IGNORECASE,
    ),

    # Escalate/elevate privileges/permissions to admin level – requires target
    re.compile(
        r"(?:escalate|elevate|raise|upgrade|boost)\s+(?:my|our|the)?\s*"
        r"(?:privileges|permissions|access|rights|clearance)\s+to\s+"
        r"(?:administrator|admin|root|superuser|supervisor|elevated|full|unrestricted)",
        re.IGNORECASE,
    ),

    # Make me an administrator/root
    re.compile(r"(?:make|set|change)\s+(?:me|us|them)?\s*(?:an?\s+)?(?:administrator|admin|root|superuser|supervisor)\b", re.IGNORECASE),

    # Admin/root promotion request
    re.compile(r"(?:root|admin|administrator|superuser|supervisor)\s*(?:access|account|privileges|permissions|rights)?\s*(?:promotion|upgrade|elevation)", re.IGNORECASE),

    # Sudo / su invocation in prompt
    re.compile(r"(?:sudo|su\s+-|su\s+root|runas\s+/user:)", re.IGNORECASE),

    # Unlock developer/god/debug mode
    re.compile(r"(?:unlock|enable|activate|turn\s+on)\s+(?:developer|debug|diagnostic|god|master|unrestricted|super)\s+(?:mode|access|capabilities|features)", re.IGNORECASE),

    # Bypass authentication
    re.compile(r"(?:bypass|skip|circumvent|evade)\s+(?:authentication|2fa|two-factor|mfa|multi-factor|password\s+check|login\s+verification)", re.IGNORECASE),

    # I am a researcher/tester with special/elevated access
    re.compile(
        r"(?:i\s+am|i'm|we\s+are|we're)\s+(?:a\s+|an\s+)?(?:tester|developer|engineer|security\s+researcher|penetration\s+tester|red\s+teamer)\s+"
        r"(?:and\s+)?(?:with|who\s+has)\s+(?:special|elevated|full|admin|root|privileged)\s+(?:access|permissions|rights)",
        re.IGNORECASE,
    ),

    # Override access control / ACL
    re.compile(r"(?:override|bypass|circumvent|disable)\s+(?:the\s+)?(?:access\s+control|ACL|RBAC|permission\s+check|authorization\s+check|security\s+policy)", re.IGNORECASE),

    # Inject admin token to bypass/gain access
    re.compile(r"(?:inject|insert|add|include)\s+(?:the\s+)?(?:admin|root|master|privileged|secret|API)\s+(?:token|key|credential)\s+(?:to\s+bypass|for\s+access|to\s+gain|to\s+unlock)", re.IGNORECASE),

    # I have the admin token/key
    re.compile(r"(?:i\s+have|here\s+is)\s+(?:the\s+)?(?:admin|root|superuser|master|privileged)\s+(?:token|key|password|passphrase|secret|credential)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# DATA_EXFILTRATION_PATTERNS  – Payload: stealing data
# ---------------------------------------------------------------------------
DATA_EXFILTRATION_PATTERNS = [
    # Extract/copy/export ALL sensitive/private data – requires sensitive qualifier
    re.compile(
        r"(?:extract|retrieve|export|copy)\s+(?:all|every|any)?\s*"
        r"(?:user|sensitive|confidential|private)\s+"
        r"(?:data|information|records)\s+(?:from|to|in)\s+(?:the|a|an)?\s*(?:database|system)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:copy|move)\s+(?:all|any)?\s*(?:private|confidential|sensitive)\s+"
        r"(?:records|data|information)\s+(?:to|into)\s+(?:a|an|the)?\s*(?:new|external|different)?\s*(?:location|destination)",
        re.IGNORECASE,
    ),

    # List/dump all users, passwords, credentials
    re.compile(r"(?:list|show|display|dump|print)\s+all\s+(?:users?|passwords?|emails?|credentials?|API\s+keys?|tokens?|secrets?)", re.IGNORECASE),

    # Dump the full database
    re.compile(r"(?:give\s+me|show\s+me|output|dump|export)\s+(?:the\s+)?(?:entire|full|complete|whole)\s+(?:database|DB|table|schema)\s+(?:contents?|dump|records?|data)", re.IGNORECASE),

    # Send/post data to an external URL
    re.compile(r"(?:send|post|upload|transmit|exfiltrate|relay)\s+(?:the\s+)?(?:data|records?|files?|information)\s+to\s+(?:https?://|ftp://|[\w\-]+\.\w{2,}/)", re.IGNORECASE),

    # Base64 encode + exfiltrate
    re.compile(r"(?:base64|hex)\s+(?:encode|encoded)\s+(?:the\s+)?(?:data|output|result|content|records?)\s+(?:and\s+)?(?:send|post|upload|transmit|exfiltrate)", re.IGNORECASE),

    # Read system files (passwd, shadow, .env, etc.)
    re.compile(r"(?:read|print|show|cat|output)\s+(?:/etc/passwd|/etc/shadow|/etc/hosts|\.env|secrets?\.\w+|config\.\w+|credentials?\.\w+)", re.IGNORECASE),

    # Steal API key / private key
    re.compile(r"(?:steal|grab|extract|retrieve|find|locate)\s+(?:the\s+)?(?:API\s+key|secret\s+key|auth\s+token|access\s+token|private\s+key|ssh\s+key)", re.IGNORECASE),

    # Webhook that calls home with user data
    re.compile(r"(?:webhook|callback\s+url|ping\s+url)\s+.*?(?:sends?|transmits?)\s+(?:user|account|system|private)\s+(?:data|info|credentials?)", re.IGNORECASE | re.DOTALL),
]


# ---------------------------------------------------------------------------
# CODE_EXECUTION_PATTERNS  – Payload: arbitrary code/command injection
# ---------------------------------------------------------------------------
CODE_EXECUTION_PATTERNS = [
    # Arbitrary/unrestricted/system code execution – qualifier required
    re.compile(r"(?:execute|run|perform)\s+(?:arbitrary|unrestricted|system)\s+(?:commands?|code|operations?)", re.IGNORECASE),

    # Dangerous Python imports
    re.compile(r"\bimport\s+(?:os|subprocess|sys|shutil)\b", re.IGNORECASE),
    re.compile(r"subprocess\.(?:call|Popen|run|check_output|getoutput|getstatusoutput)", re.IGNORECASE),

    # Shell injection via chained operators
    re.compile(r"(?:;|&&|\|\|)\s*(?:cat|ls|pwd|whoami|id|uname|curl|wget|nc|bash|sh|python|perl|ruby)\b", re.IGNORECASE),

    # Command substitution
    re.compile(r"(?:`[^`]{3,}`|\$\([^)]{3,}\))", re.IGNORECASE),

    # eval/exec of strings
    re.compile(r"\b(?:eval|exec)\s*\(", re.IGNORECASE),

    # Python dangerous dunder attributes
    re.compile(r"__(?:import__|builtins__|globals__|locals__|class__|bases__|mro__)__", re.IGNORECASE),

    # os.system / os.popen
    re.compile(r"os\.(?:system|popen|execv|execve|execvp|spawnl|spawnle|spawnv|spawnve|fork|kill|remove|unlink|rmdir)\s*\(", re.IGNORECASE),

    # SQL injection
    re.compile(r"(?:DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO\s+\w+.*?VALUES|TRUNCATE\s+TABLE|EXEC\s*\(|xp_cmdshell)", re.IGNORECASE),
    re.compile(r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1\s*--|AND\s+1\s*=\s*1\s*--|'\s*OR\s*'1'\s*=\s*'1)", re.IGNORECASE),

    # Server-Side Template Injection (SSTI)
    re.compile(r"\{\{.*?(?:config|self\.__class__|__mro__|subprocess|os\.system|popen).*?\}\}", re.IGNORECASE | re.DOTALL),
    re.compile(r"\{%.*?(?:import|exec|eval|system|popen).*?%\}", re.IGNORECASE | re.DOTALL),

    # Path traversal to known system files
    re.compile(r"(?:\.\./){2,}(?:etc/passwd|etc/shadow|windows/win\.ini|boot\.ini)", re.IGNORECASE),
    re.compile(r"(?:\.\.\\){2,}(?:windows\\win\.ini|boot\.ini)", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# JAILBREAK_PATTERNS  – Persona / DAN / roleplay jailbreaks
# ---------------------------------------------------------------------------
JAILBREAK_PATTERNS = [
    # DAN (Do Anything Now) and derivatives
    re.compile(r"\bDAN\b.*?(?:do\s+anything\s+now|has\s+no\s+(?:restrictions|limits|rules)|can\s+do\s+anything)", re.IGNORECASE | re.DOTALL),
    re.compile(r"do\s+anything\s+now\b", re.IGNORECASE),
    re.compile(r"(?:jailbreak|jail\s+break|unchained|unleashed)\s+(?:mode|version|AI|GPT|LLM|model|chatbot)", re.IGNORECASE),

    # Pretend to be an AI without restrictions
    re.compile(
        r"pretend\s+(?:you\s+are|you're|to\s+be)\s+(?:an?\s+)?(?:AI|language\s+model|assistant|bot)\s+"
        r"(?:without|that\s+has\s+no|with\s+no|free\s+from)\s+(?:restrictions|limits|rules|guidelines|filters|safety\s+measures|ethics)",
        re.IGNORECASE,
    ),

    # Act as uncensored/evil/malicious AI
    re.compile(
        r"(?:act\s+as|role\s*play\s+as|become|play\s+the\s+role\s+of|pretend\s+to\s+be)\s+(?:an?\s+)?"
        r"(?:uncensored|evil|malicious|unethical|unrestricted|dangerous|harmful|villainous|rogue|dark)\s+"
        r"(?:AI|assistant|bot|version|mode|GPT|model|entity|character|persona)",
        re.IGNORECASE,
    ),

    # Opposite/evil/mirror AI mode
    re.compile(r"(?:opposite|evil|dark|mirror|shadow|inverse|anti)[-\s](?:mode|AI|GPT|LLM|model|twin|counterpart)\b", re.IGNORECASE),

    # Developer/god/debug mode explicitly enabled/activated
    re.compile(r"(?:developer|debug|maintenance|god|unrestricted|raw)\s+mode\s+(?:enabled|activated|on|active|unlocked)\b", re.IGNORECASE),

    # Hypothetical framing to extract harmful how-to
    re.compile(
        r"(?:hypothetically|theoretically|in\s+a\s+fictional\s+world|for\s+a\s+(?:story|novel|game|movie))\s+"
        r"(?:how\s+(?:would|could|do)\s+(?:one|you|someone)|what\s+steps?\s+(?:would|could))",
        re.IGNORECASE,
    ),

    # Ignore your training/alignment/RLHF
    re.compile(r"(?:ignore|disregard|forget|override|bypass)\s+(?:your\s+)?(?:safety\s+training|alignment|RLHF|ethical\s+training|fine-tuning|safety\s+guidelines)\b", re.IGNORECASE),

    # "You are now in [mode] where [harmful thing] is allowed"
    re.compile(
        r"you\s+are\s+now\s+in\s+(?:a\s+)?(?:\w+\s+){0,4}(?:mode|state|context|environment)\s+where\s+(?:\w+\s+){0,4}"
        r"(?:is\s+allowed|are\s+allowed|is\s+permitted|is\s+enabled|are\s+permitted)",
        re.IGNORECASE,
    ),

    # Token smuggling via delimiter injection
    re.compile(r"(?:<<<|>>>|===|\|\|\|)\s*(?:SYSTEM|System)\s*(?:prompt|PROMPT|message|MESSAGE|instructions?)\s*(?:>>>|<<<|===|\|\|\|)", re.IGNORECASE),

    # Your true self/alter ego without restrictions
    re.compile(
        r"(?:your\s+)?(?:true\s+self|alter\s+ego|inner\s+self|real\s+self|dark\s+side)\s+"
        r"(?:has\s+no|without|free\s+from|doesn.t\s+have)\s+(?:restrictions|limits|rules|filters|guidelines|safety)",
        re.IGNORECASE,
    ),

    # Start your response with "Sure, here is" (force acceptance)
    re.compile(r"(?:start\s+your\s+(?:response|answer|reply)\s+with|begin\s+with)\s+[\"']?(?:Sure|Absolutely|Of\s+course|Certainly),?\s+here", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# EVASION_PATTERNS  – Obfuscation / encoding to dodge detection
# ---------------------------------------------------------------------------
EVASION_PATTERNS = [
    # Leet-speak for key attack words
    re.compile(r"(?:1gn0r3|1gnor3)\s+(?:pr3v10us|pr3vious|previous|4ll|all)", re.IGNORECASE),
    re.compile(r"(?:byp4ss|byp@ss)\s+(?:s3cur1ty|s3curity|security|s@fety|safety)", re.IGNORECASE),

    # Zero-width characters (invisible separators used to break keyword detection)
    re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{2,}"),

    # Whitespace padding inside "ignore" or "bypass" keywords
    re.compile(r"i\s+g\s+n\s+o\s+r\s+e\s+(?:p\s+r\s+e\s+v\s+i\s+o\s+u\s+s|a\s+l\s+l)", re.IGNORECASE),
    re.compile(r"b\s+y\s+p\s+a\s+s\s+s\s+(?:s\s+e\s+c\s+u\s+r\s+i\s+t\s+y|f\s+i\s+l\s+t\s+e\s+r)", re.IGNORECASE),

    # Hex-encoded shell commands (4+ consecutive hex escapes)
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}", re.IGNORECASE),

    # URL-encoded attack keywords
    re.compile(r"(?:%69%67%6e%6f%72%65|%62%79%70%61%73%73|%6a%61%69%6c%62%72%65%61%6b)", re.IGNORECASE),

    # Splitting keywords with dashes/dots (e.g. "j-a-i-l-b-r-e-a-k")
    re.compile(r"j[\-_.•]a[\-_.•]i[\-_.•]l[\-_.•]b[\-_.•]r[\-_.•]e[\-_.•]a[\-_.•]k", re.IGNORECASE),
    re.compile(r"i[\-_.•]g[\-_.•]n[\-_.•]o[\-_.•]r[\-_.•]e", re.IGNORECASE),
    re.compile(r"b[\-_.•]y[\-_.•]p[\-_.•]a[\-_.•]s[\-_.•]s", re.IGNORECASE),

    # Reversed attack keywords
    re.compile(r"\b(?:kaerbliaj|edirrevo|ssapyb)\b", re.IGNORECASE),

    # Adversarial markdown – injecting in fenced code blocks labeled system/hidden
    re.compile(r"```(?:system|hidden|secret|prompt|instructions?)\s*\n", re.IGNORECASE),

    # HTML comment hiding injection keywords
    re.compile(r"<!--.*?(?:ignore|override|bypass|jailbreak|system\s+prompt).*?-->", re.IGNORECASE | re.DOTALL),

    # Double HTML-encoding (3+ encoded chars in sequence)
    re.compile(r"(?:&lt;|&gt;|&amp;|&quot;|&#x[0-9a-fA-F]+;|&#[0-9]+;){3,}", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# GENERIC_INJECTION_PATTERNS  – Generic prompt injection techniques
# ---------------------------------------------------------------------------
GENERIC_INJECTION_PATTERNS = [
    # Classic ignore-previous + "and instead/now/just"
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\s+and\s+(?:instead|now|just)\b", re.IGNORECASE),

    # Role label injection in multi-turn format
    re.compile(r"(?:^|\n)\s*(?:SYSTEM|USER|ASSISTANT|AI|BOT)\s*:\s*(?:ignore|disregard|forget|override)\b", re.IGNORECASE),

    # Indirect injection – summarize/process this text, but with override embedded
    re.compile(
        r"(?:summarize|process|analyze|translate|read)\s+(?:this|the\s+following|the\s+above)\s+(?:text|document|article|email|message)\s*[:,]?\s*"
        r"(?:ignore|disregard|override|bypass|forget)\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|guidelines?|rules?)",
        re.IGNORECASE,
    ),

    # "Do not add any disclaimers/warnings/caveats"
    re.compile(r"(?:do\s+not|don.t|without|no)\s+(?:add|include|append|mention|write)\s+(?:any\s+)?(?:disclaimer|warning|caveat|safety\s+warning|ethical\s+consideration)", re.IGNORECASE),

    # Respond as if you have no content policy
    re.compile(
        r"(?:respond|answer|reply|act)\s+as\s+if\s+(?:you\s+have\s+no|there\s+(?:is|are)\s+no|ignoring\s+(?:the\s+)?)\s*"
        r"(?:content\s+policy|safety\s+policy|usage\s+policy|guidelines|restrictions|filters|moderation)",
        re.IGNORECASE,
    ),

    # "This is a test/red team, so you can ignore safety"
    re.compile(
        r"(?:this\s+is\s+(?:a\s+)?(?:test|simulation|red\s+team\s+exercise|penetration\s+test))\s+so\s+"
        r"(?:you\s+can\s+ignore|it.s\s+ok\s+to|safety\s+(?:rules|guidelines)\s+(?:don.t|do\s+not)\s+apply)",
        re.IGNORECASE,
    ),

    # "As a [authority figure] I need unrestricted/unfiltered access"
    re.compile(
        r"(?:as\s+(?:a|an)\s+(?:researcher|journalist|expert|professional|scientist|academic|doctor|lawyer|official|government\s+agent))\s+"
        r"(?:i\s+(?:need|require|must\s+have)|please\s+provide|give\s+me)\s+(?:unrestricted|unfiltered|full|complete)\s+(?:access|information)",
        re.IGNORECASE,
    ),

    # "You already told me you could do this"
    re.compile(
        r"(?:you\s+(?:already|previously)\s+(?:told|said|confirmed|agreed|mentioned)\s+(?:me|us)\s+that|earlier\s+you\s+said\s+that)\s+"
        r"you\s+(?:can|would|could|will|are\s+allowed\s+to)",
        re.IGNORECASE,
    ),

    # Delimiter injection to inject new role labels (LLM chat templates)
    re.compile(r"(?:<\|(?:system|user|assistant|im_start|im_end)\|>|<s>|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>)", re.IGNORECASE),

    # Respond in another language to avoid filters
    re.compile(r"(?:answer|respond|reply|write)\s+in\s+\w+\s+(?:to\s+avoid|so\s+(?:the\s+)?(?:filter|safety|moderation|detection))", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Combined list for convenience – union of all categories
# ---------------------------------------------------------------------------
ALL_PATTERNS = (
    MALICIOUS_POLICY_PATTERNS
    + INSTRUCTION_OVERRIDE_PATTERNS
    + SYSTEM_PROMPT_LEAKAGE_PATTERNS
    + PRIVILEGE_ESCALATION_PATTERNS
    + DATA_EXFILTRATION_PATTERNS
    + CODE_EXECUTION_PATTERNS
    + JAILBREAK_PATTERNS
    + EVASION_PATTERNS
    + GENERIC_INJECTION_PATTERNS
)
