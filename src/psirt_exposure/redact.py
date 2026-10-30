"""Mask secrets in config lines before they appear as evidence in output or reports."""

from __future__ import annotations

import re

MASK = "<redacted>"

# A secret value: a quoted string (may contain spaces) or one token.
_VAL = r'(?:"[^"]*"|\S+)'
# Optional encryption type (0 plain, 5/6/7/8/9 hashed or encrypted) before a value.
_TYPE = r"(?: [0-9])?"

_RULES: tuple[re.Pattern[str], ...] = (
    re.compile(rf"^(snmp-server community{_TYPE} )({_VAL})"),
    re.compile(
        r"^(snmp-server host \S+(?: (?:vrf \S+|informs|traps"
        rf"|version (?:1|2c|3(?: (?:auth|noauth|priv))?)))*) ({_VAL})"
    ),
    re.compile(
        r"\b(auth (?:md5|sha(?:-?\d+)?|hmac-\S+)(?: (?:2 )?(?:224|256|384|512))?"
        rf"{_TYPE} )({_VAL})"
    ),
    re.compile(rf"\b(priv (?:des\S*|3des|aes(?: \d+)?){_TYPE} )({_VAL})"),
    re.compile(rf"\b((?:secret|password){_TYPE} )({_VAL})"),
    re.compile(
        r"\b(pre-shared-key(?: (?:local|remote))?(?: address \S+(?: \S+)?)?(?: key)?"
        rf"{_TYPE}(?: hex)? )({_VAL})"
    ),
    re.compile(rf"^(crypto isakmp key{_TYPE} )({_VAL})"),
    re.compile(
        rf"(?<![-\w])(key(?:-string)?{_TYPE} )"
        rf"(?!(?:generate|chain|config-key|storage|zeroize|export|import|pubkey)\b)({_VAL})"
    ),
)


def redact(text: str) -> str:
    """Replace secret values (communities, passwords, hashes, keys) with ``<redacted>``."""
    for rx in _RULES:
        text = rx.sub(lambda m: m.group(1) + MASK, text)
    return text
