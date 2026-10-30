"""Mask secrets in config lines before they appear as evidence in output or reports."""

from __future__ import annotations

import re

MASK = "<redacted>"

_RULES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^(snmp-server community )(\S+)"),
    re.compile(r"\b(auth (?:md5|sha\S*) )(\S+)"),
    re.compile(r"\b(priv (?:des\S*|3des|aes(?: \d+)?) )(\S+)"),
    re.compile(r"\b((?:secret|password)(?: \d+)? )(\S+)"),
    re.compile(r"\b(pre-shared-key(?: local| remote)?(?: \d+)? )(\S+)"),
    re.compile(r"^(crypto isakmp key(?: \d+)? )(\S+)"),
    re.compile(r"\b(key(?:-string)? \d+ )(\S+)"),
    re.compile(r"^(key(?:-string)? )(?!\d+ )(\S+)"),
)


def redact(text: str) -> str:
    """Replace secret values (communities, passwords, hashes, keys) with ``<redacted>``."""
    for rx in _RULES:
        text = rx.sub(lambda m: m.group(1) + MASK, text)
    return text
