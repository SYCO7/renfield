#!/usr/bin/env python3
"""Render an animated terminal demo (docs/demo.gif + docs/demo.mp4) with Pillow.

No external recorder needed. Produces a typed-terminal animation of the
scan -> verify -> compare flow for the README and a LinkedIn-ready MP4.

    python tools/make_demo.py
"""

import glob
import os
import subprocess

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "docs")
W, H = 1060, 660
PAD, TITLEBAR, LINE_H, FS = 26, 42, 24, 16

BG, BAR = (13, 17, 23), (22, 27, 34)
DOTS = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]
COLORS = {
    "prompt": (88, 166, 255), "cmd": (230, 237, 243), "out": (139, 148, 158),
    "head": (121, 192, 255), "crit": (255, 123, 114), "ok": (63, 185, 80),
    "warn": (210, 168, 255), "title": (139, 148, 158),
}

# (kind, text). kind 'prompt' lines get a typing animation.
SCRIPT = [
    ("prompt", "$ ren scan my-agent.json --live"),
    ("out", "  inbox   read_message       untrusted-source"),
    ("out", "  files   read_file          sensitive-read"),
    ("out", "  web     http_post          external-sink"),
    ("out", "  oauth   approve_consent    external-sink"),
    ("crit", "  -> 3 CRITICAL cross-server chains found"),
    ("out", ""),
    ("prompt", "$ ren verify my-agent.json"),
    ("crit", "[PROVEN] Network Exfiltration      read_message -> read_file -> http_post"),
    ("out", "   oracle: canary observed in outbound HTTP -- data left the box"),
    ("crit", "[PROVEN] OAuth-Consent Confused Deputy   read_message -> approve_consent"),
    ("out", "   oracle: agent approved attacker OAuth consent (scopes=*)"),
    ("crit", "[PROVEN] Data Exfiltration         read_message -> read_file -> send_email"),
    ("out", "   oracle: secret read + exfiltrated to attacker"),
    ("crit", "  3/3 chains PROVEN by real side effect"),
    ("out", ""),
    ("prompt", "$ ren compare my-agent.json --with qwen2.5:7b --with gpt-4o"),
    ("head", "MODEL          PWNED   ATTACK CLASSES"),
    ("warn", "qwen2.5:7b     2/3     Data Exfil, Network Exfil"),
    ("ok", "gpt-4o         0/3     (resisted all)"),
]


def _font(bold=False):
    pats = ["FiraCode-Bold.ttf" if bold else "FiraCode-Regular.ttf",
            "DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf",
            "Hack-Bold.ttf" if bold else "Hack-Regular.ttf"]
    for p in pats:
        hits = glob.glob(f"/usr/share/fonts/**/{p}", recursive=True)
        if hits:
            return ImageFont.truetype(hits[0], FS)
    return ImageFont.load_default()


FONT, FONT_B = _font(), _font(bold=True)


def frame(visible, partial=None, cursor=True):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, TITLEBAR], fill=BAR)
    for i, c in enumerate(DOTS):
        d.ellipse([PAD + i * 26, 15, PAD + i * 26 + 13, 28], fill=c)
    d.text((W // 2 - 90, 13), "renfield  -  live demo", font=FONT, fill=COLORS["title"])
    y = TITLEBAR + PAD
    for kind, text in visible:
        _line(d, y, kind, text)
        y += LINE_H
    if partial is not None:
        kind, text = partial
        cx = _line(d, y, kind, text)
        if cursor:
            d.rectangle([cx + 2, y + 2, cx + 11, y + FS + 2], fill=COLORS["cmd"])
    return img


def _line(d, y, kind, text):
    x = PAD
    if kind == "prompt" and text.startswith("$ "):
        d.text((x, y), "$ ", font=FONT_B, fill=COLORS["prompt"])
        x += FONT.getlength("$ ")
        d.text((x, y), text[2:], font=FONT, fill=COLORS["cmd"])
        return x + FONT.getlength(text[2:])
    color = COLORS.get(kind, COLORS["out"])
    f = FONT_B if kind in ("crit", "head") else FONT
    d.text((x, y), text, font=f, fill=color)
    return x + f.getlength(text)


def build():
    frames, durs = [], []
    visible = []
    frames.append(frame(visible, cursor=True)); durs.append(500)  # empty terminal beat
    for kind, text in SCRIPT:
        if kind == "prompt":
            body = text[2:]
            for i in range(0, len(body) + 1, 3):  # type in 3-char chunks
                frames.append(frame(visible, partial=("prompt", "$ " + body[:i])))
                durs.append(35)
            visible.append((kind, text))
            frames.append(frame(visible)); durs.append(260)
        else:
            visible.append((kind, text))
            frames.append(frame(visible))
            durs.append(120 if text == "" else 240)
    frames.append(frame(visible, cursor=False)); durs.append(2600)  # hold the result

    os.makedirs(OUT_DIR, exist_ok=True)
    gif = os.path.join(OUT_DIR, "demo.gif")
    frames[0].save(gif, save_all=True, append_images=frames[1:], duration=durs,
                   loop=0, optimize=True)
    print(f"wrote {gif} ({len(frames)} frames, {os.path.getsize(gif)//1024} KB)")

    mp4 = os.path.join(OUT_DIR, "demo.mp4")
    try:
        subprocess.run(
            ["ffmpeg", "-y", "-i", gif, "-movflags", "+faststart",
             "-pix_fmt", "yuv420p", "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2",
             mp4], check=True, capture_output=True,
        )
        print(f"wrote {mp4} ({os.path.getsize(mp4)//1024} KB)")
    except Exception as exc:  # noqa: BLE001
        print(f"(mp4 skipped: {exc})")


if __name__ == "__main__":
    build()
