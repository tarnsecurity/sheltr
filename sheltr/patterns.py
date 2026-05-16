"""
sheltr/patterns.py

A library of regex patterns for detecting hardcoded secrets.
Each pattern has a name, regex, severity, and description.
"""

import re

# Severity levels
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

PATTERNS = [
    # --- API Keys ---
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'(?i)(AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
        "severity": HIGH,
        "description": "Amazon Web Services access key ID",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        "severity": HIGH,
        "description": "Amazon Web Services secret access key",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}'),
        "severity": HIGH,
        "description": "GitHub personal access or OAuth token",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": re.compile(r'sk_(live|test)_[A-Za-z0-9]{24,}'),
        "severity": HIGH,
        "description": "Stripe secret API key",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": re.compile(r'pk_(live|test)_[A-Za-z0-9]{24,}'),
        "severity": MEDIUM,
        "description": "Stripe publishable API key",
    },
    {
        "name": "Slack Bot Token",
        "pattern": re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}'),
        "severity": HIGH,
        "description": "Slack bot token",
    },
    {
        "name": "Slack User Token",
        "pattern": re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}'),
        "severity": HIGH,
        "description": "Slack user token",
    },
    {
        "name": "Slack Webhook URL",
        "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8,}/B[A-Za-z0-9_]{8,}/[A-Za-z0-9_]{24}'),
        "severity": HIGH,
        "description": "Slack incoming webhook URL",
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "severity": HIGH,
        "description": "Google API key",
    },
    {
        "name": "Twilio API Key",
        "pattern": re.compile(r'SK[0-9a-fA-F]{32}'),
        "severity": HIGH,
        "description": "Twilio API key",
    },
    {
        "name": "SendGrid API Key",
        "pattern": re.compile(r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
        "severity": HIGH,
        "description": "SendGrid API key",
    },
    {
        "name": "Mailgun API Key",
        "pattern": re.compile(r'key-[0-9a-zA-Z]{32}'),
        "severity": HIGH,
        "description": "Mailgun API key",
    },
    {
        "name": "NPM Token",
        "pattern": re.compile(r'npm_[A-Za-z0-9]{36}'),
        "severity": HIGH,
        "description": "NPM access token",
    },
    {
        "name": "PyPI Token",
        "pattern": re.compile(r'pypi-[A-Za-z0-9_\-]{50,}'),
        "severity": HIGH,
        "description": "PyPI API token",
    },
    {
        "name": "Anthropic API Key",
        "pattern": re.compile(r'sk-ant-[A-Za-z0-9\-_]{40,}'),
        "severity": HIGH,
        "description": "Anthropic API key",
    },
    {
        "name": "OpenAI API Key",
        "pattern": re.compile(r'sk-[A-Za-z0-9]{48}'),
        "severity": HIGH,
        "description": "OpenAI API key",
    },

    # --- Private Keys & Certs ---
    {
        "name": "RSA Private Key",
        "pattern": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        "severity": HIGH,
        "description": "RSA private key",
    },
    {
        "name": "Private Key (generic)",
        "pattern": re.compile(r'-----BEGIN (EC|PGP|DSA|OPENSSH) PRIVATE KEY-----'),
        "severity": HIGH,
        "description": "Private cryptographic key",
    },
    {
        "name": "Certificate",
        "pattern": re.compile(r'-----BEGIN CERTIFICATE-----'),
        "severity": LOW,
        "description": "Public certificate (may be intentional)",
    },

    # --- Passwords & Generic Secrets ---
    {
        "name": "Generic Password Assignment",
        "pattern": re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']'),
        "severity": MEDIUM,
        "description": "Hardcoded password in assignment",
    },
    {
        "name": "Generic Secret Assignment",
        "pattern": re.compile(r'(?i)(secret|secret_key|secret_token)\s*[=:]\s*["\']([^"\']{8,})["\']'),
        "severity": MEDIUM,
        "description": "Hardcoded secret value",
    },
    {
        "name": "Generic Token Assignment",
        "pattern": re.compile(r'(?i)(token|api_token|access_token|auth_token)\s*[=:]\s*["\']([^"\'A-Z]{8,})["\']'),
        "severity": MEDIUM,
        "description": "Hardcoded token value",
    },

    # --- Connection Strings ---
    {
        "name": "Database URL with credentials",
        "pattern": re.compile(r'(?i)(postgres|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@[^\s"\']+'),
        "severity": HIGH,
        "description": "Database connection string with embedded credentials",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
        "severity": MEDIUM,
        "description": "JSON Web Token (may be hardcoded)",
    },
]
