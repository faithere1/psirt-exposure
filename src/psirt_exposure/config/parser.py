"""Parse an IOS XE running configuration into a platform-agnostic line tree.

ciscoconfparse2 does the indentation and banner handling; the matcher only sees the small
``ConfigLine`` / ``DeviceConfig`` interface below, so other platforms (NX-OS, ASA) can plug in a
different parser later.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ciscoconfparse2 import CiscoConfParse  # type: ignore[import-untyped]


@dataclass(frozen=True)
class ConfigLine:
    """One configuration line. ``text`` is stripped; ``number`` is 1-based in the source file."""

    number: int
    text: str
    children: tuple[ConfigLine, ...] = ()

    def descendants(self) -> list[ConfigLine]:
        """Every line below this one, depth first, in file order."""
        out: list[ConfigLine] = []
        for child in self.children:
            out.append(child)
            out.extend(child.descendants())
        return out


@dataclass(frozen=True)
class DeviceConfig:
    """A parsed configuration: the top-level lines with their child trees."""

    lines: tuple[ConfigLine, ...] = field(default_factory=tuple)


def _skip(text: str) -> bool:
    return not text or text.startswith("!")


def _convert(obj: object) -> ConfigLine:
    kids = tuple(_convert(c) for c in obj.children if not _skip(c.text.strip()))  # type: ignore[attr-defined]
    return ConfigLine(number=obj.linenum + 1, text=obj.text.strip(), children=kids)  # type: ignore[attr-defined]


def parse_config(text: str) -> DeviceConfig:
    """Parse ``show running-config`` output. Comment (``!``) and blank lines are dropped."""
    parse = CiscoConfParse(text.splitlines(), syntax="ios")
    top = [o for o in parse.objs if o.parent is o and not _skip(o.text.strip())]
    return DeviceConfig(lines=tuple(_convert(o) for o in top))
