# /// script
# requires-python = ">=3.11"
# dependencies = ["pillow>=11"]
# ///
"""Render docs/demo.gif from real netsec-check runs.

Run from the repo root:  uv run --with pillow python scripts/demo_gif.py

The commands run for real on a temporary copy of rules/, samples/configs/ and
tests/fixtures/psirt/, so the GIF shows actual output. Only the bundled fake sample data is used.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo.gif"

COLS, ROWS = 104, 20
FONT_SIZE, LINE_H, PAD = 14, 19, 16
BG, FG, DIM = (24, 26, 33), (220, 223, 228), (128, 134, 148)
PROMPT, CMD = (97, 175, 239), (255, 255, 255)
VERDICT_COLORS = {
    "NOT_AFFECTED_FEATURE_DISABLED": (152, 195, 121),
    "FIXED_VERSION": (152, 195, 121),
    "INDETERMINATE": (198, 120, 221),
    "MITIGATED": (229, 192, 123),
    "AFFECTED": (224, 108, 117),
}

FONTS = ("/System/Library/Fonts/Menlo.ttc", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")

Span = tuple[str, tuple[int, int, int]]


@dataclass
class Frame:
    lines: list[list[Span]]
    ms: int


def _font() -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONTS:
        if Path(path).exists():
            return ImageFont.truetype(path, FONT_SIZE)
    return ImageFont.load_default()


def colorize(line: str) -> list[Span]:
    """Color a CLI output line: verdicts by severity, evidence and reasons dimmed."""
    if line.startswith("    "):
        return [(line, DIM)]
    if line.startswith("verdict ") or "-> AFFECTED" in line:
        return [(line, VERDICT_COLORS["AFFECTED"])]
    for word, color in VERDICT_COLORS.items():
        idx = line.find(f" {word} ")
        if idx >= 0:
            start = idx + 1
            return [(line[:start], FG), (word, color), (line[start + len(word) :], FG)]
    return [(line, FG)]


class Terminal:
    def __init__(self) -> None:
        self.lines: list[list[Span]] = []
        self.frames: list[Frame] = []

    def _snap(self, ms: int) -> None:
        self.frames.append(Frame([list(line) for line in self.lines[-ROWS:]], ms))

    def clear(self) -> None:
        self.lines = []

    def type(self, command: str, pause: int = 600) -> None:
        self.lines.append([("$ ", PROMPT)])
        self._snap(400)
        for end in range(3, len(command) + 3, 3):
            self.lines[-1] = [("$ ", PROMPT), (command[:end], CMD)]
            self._snap(35)
        self._snap(pause)

    def output(self, text: str, hold: int) -> None:
        for raw in text.rstrip("\n").splitlines():
            self.lines.append(colorize(raw[:COLS]))
        self._snap(hold)

    def comment(self, text: str, hold: int = 900) -> None:
        self.lines.append([(f"# {text}", DIM)])
        self._snap(hold)


def run(cwd: Path, *args: str) -> str:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "COLUMNS": str(COLS)}
    code = "import sys; from netsec_check.cli import main; sys.exit(main())"
    proc = subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout + proc.stderr


def build(work: Path) -> list[Frame]:
    term = Terminal()

    term.comment("Is edge-rtr-01 affected? Version check + config evidence, fully offline.")
    args = ["check", "--offline", "--device", "edge-rtr-01"]
    args += ["--rule", "ikev2", "--rule", "snmp", "--rule", "webui", "--evidence"]
    term.type("netsec-check " + " ".join(args))
    term.output(run(work, *args), 5500)

    term.clear()
    term.comment("Drift watch: save a baseline, change a config, see the new exposure.")
    term.type("netsec-check watch --offline", 300)
    term.output(run(work, "watch", "--offline"), 1500)
    config = work / "samples/configs/edge-rtr-02/running-config.txt"
    line = "snmp-server community EXAMPLE-RW RW"
    term.type(f"echo '{line}' >> samples/configs/edge-rtr-02/running-config.txt", 300)
    with config.open("a") as fh:
        fh.write(line + "\n")
    term.type("netsec-check watch --offline", 300)
    term.output(run(work, "watch", "--offline"), 6000)
    return term.frames


def render(frames: list[Frame]) -> list[Image.Image]:
    font = _font()
    char_w = font.getlength("M") if isinstance(font, ImageFont.FreeTypeFont) else 7
    size = (int(PAD * 2 + COLS * char_w), PAD * 2 + ROWS * LINE_H)
    images = []
    for frame in frames:
        img = Image.new("RGB", size, BG)
        draw = ImageDraw.Draw(img)
        for row, spans in enumerate(frame.lines):
            x = float(PAD)
            for text, color in spans:
                draw.text((x, PAD + row * LINE_H), text, font=font, fill=color)
                x += len(text) * char_w
        images.append(img.quantize(colors=128, method=Image.Quantize.FASTOCTREE))
    return images


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for rel in ("rules", "samples/configs", "tests/fixtures/psirt"):
            shutil.copytree(ROOT / rel, work / rel)
        frames = build(work)
    images = render(frames)
    OUT.parent.mkdir(exist_ok=True)
    images[0].save(
        OUT,
        save_all=True,
        append_images=images[1:],
        duration=[f.ms for f in frames],
        loop=0,
        optimize=True,
    )
    print(f"wrote {OUT.relative_to(ROOT)} ({len(frames)} frames, {OUT.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()
