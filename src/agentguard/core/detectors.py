"""Credential-format detectors (§6.1, §6.7).

Each match is indexed as its own protected value with the `secret` label, so a leaked API key
is caught even when it sits inside a document that is otherwise harmless.
"""

from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key id
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),  # GitHub tokens
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),  # Slack tokens
    re.compile(r"sk_live_[A-Za-z0-9]{16,}"),  # Stripe live key
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),  # Google API key
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),  # OpenAI/Anthropic style keys
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),  # JWT
    re.compile(
        r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z]+ )?PRIVATE KEY-----",
        re.DOTALL,
    ),
]


def find_secrets(text: str) -> list[str]:
    """Return every substring that looks like a credential."""
    return [match.group(0) for pattern in _PATTERNS for match in pattern.finditer(text)]
