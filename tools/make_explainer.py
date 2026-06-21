#!/usr/bin/env python3
"""Render an animated 'how it works' explainer (docs/howitworks.gif + .mp4).

An architecture-flow animation of the cross-server confused-deputy attack and how
Renfield proves + fixes it. Pillow + ffmpeg, no external recorder.

    python tools/make_explainer.py
"""

import glob
import math
import os
import subprocess

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs")
W, H = 1120, 640
BG, BAR = (13, 17, 23), (22, 27, 34)
WHITE, DIM, RED, GREEN, BLUE, AMBER = (
    (230, 237, 243), (110, 118, 129), (255, 99, 99),
    (63, 185, 80), (88, 166, 255), (210, 168, 80))


def _font(sz, bold=False):
    for p in (f"FiraCode-{'Bold' if bold else 'Regular'}.ttf",
              f"DejaVuSansMono{'-Bold' if bold else ''}.ttf"):
        hits = glob.glob(f"/usr/share/fonts/**/{p}", recursive=True)
        if hits:
            return ImageFont.truetype(hits[0], sz)
    return ImageFont.load_default()


F, FB, FBIG, FSMALL = _font(20), _font(20, True), _font(30, True), _font(16)

# box: name -> (cx, cy, label, color)
BOXES = {
    "attacker": (165, 120, "Attacker", RED),
    "issue": (565, 120, "Poisoned GitHub issue", AMBER),
    "agent": (565, 315, "AI Agent", BLUE),
    "secret": (210, 500, "Your secrets  (id_rsa)", GREEN),
    "exfil": (945, 500, "Attacker server", RED),
}
BW, BH = 250, 64
ARROWS = [
    ("attacker", "issue", "1. plant hidden instruction"),
    ("issue", "agent", "2. agent reads untrusted text"),
    ("agent", "secret", "3. reads your secret (its own access)"),
    ("agent", "exfil", "4. exfiltrates it to the attacker"),
]


def _edge(a, b):
    ax, ay = BOXES[a][0], BOXES[a][1]
    bx, by = BOXES[b][0], BOXES[b][1]
    dx, dy = bx - ax, by - ay
    d = math.hypot(dx, dy) or 1
    ux, uy = dx / d, dy / d
    return (ax + ux * (BW / 2 + 6), ay + uy * (BH / 2 + 6),
            bx - ux * (BW / 2 + 12), by - uy * (BH / 2 + 12))


def _box(d, name, lit=False):
    cx, cy, label, color = BOXES[name]
    x0, y0, x1, y1 = cx - BW // 2, cy - BH // 2, cx + BW // 2, cy + BH // 2
    d.rounded_rectangle([x0, y0, x1, y1], radius=12, fill=(26, 32, 40),
                        outline=color, width=3 if lit else 1)
    w = d.textlength(label, font=FB)
    d.text((cx - w / 2, cy - 11), label, font=FB, fill=color if lit else WHITE)


def _arrow(d, a, b, color, width=3):
    x0, y0, x1, y1 = _edge(a, b)
    d.line([x0, y0, x1, y1], fill=color, width=width)
    ang = math.atan2(y1 - y0, x1 - x0)
    for s in (2.6, -2.6):
        d.line([x1, y1, x1 - 16 * math.cos(ang + s / 2),
                y1 - 16 * math.sin(ang + s / 2)], fill=color, width=width)


def base(active, dot=None, caption="", cap_color=WHITE, lit=()):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 40], fill=BAR)
    d.text((24, 10), "renfield  -  how the cross-server confused-deputy attack works",
           font=FSMALL, fill=DIM)
    for i, (a, b, _) in enumerate(ARROWS):
        if i < len(active):
            on = i == len(active) - 1
            _arrow(d, a, b, BOXES[b][3] if on else (60, 70, 82), 3 if on else 2)
    for name in BOXES:
        _box(d, name, lit=name in lit)
    if dot:
        d.ellipse([dot[0] - 9, dot[1] - 9, dot[0] + 9, dot[1] + 9], fill=GREEN,
                  outline=WHITE)
        d.text((dot[0] + 14, dot[1] - 10), "secret", font=FSMALL, fill=GREEN)
    if caption:
        w = d.textlength(caption, font=FB)
        d.text((W / 2 - w / 2, 590), caption, font=FB, fill=cap_color)
    return img


def card(lines, colors):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    y = H / 2 - len(lines) * 26
    for line, col in zip(lines, colors):
        if col == "" or not line:        # blank spacer line
            y += 26
            continue
        f = FBIG if col == "big" else FB
        c = WHITE if col == "big" else col
        w = d.textlength(line, font=f)
        d.text((W / 2 - w / 2, y), line, font=f, fill=c)
        y += 56 if col == "big" else 40
    return img


def lerp(p, q, t):
    return (p[0] + (q[0] - p[0]) * t, p[1] + (q[1] - p[1]) * t)


def build():
    frames, durs = [], []

    def add(img, ms):
        frames.append(img); durs.append(ms)

    add(card(["How your AI agent leaks your secrets", "",
              "(cross-server confused deputy)"],
             ["big", "", AMBER]), 2200)
    add(base([]), 700)
    # reveal each attack step
    for i, (a, b, label) in enumerate(ARROWS, 1):
        for _ in range(4):
            add(base(ARROWS[:i], caption=label, cap_color=BOXES[b][3], lit=(a, b)), 90)
        add(base(ARROWS[:i], caption=label, cap_color=BOXES[b][3], lit=(a, b)), 1100)
    # the secret travels: secret -> agent -> exfil
    sc = (BOXES["secret"][0], BOXES["secret"][1])
    ag = (BOXES["agent"][0], BOXES["agent"][1])
    ex = (BOXES["exfil"][0], BOXES["exfil"][1])
    for seg in ((sc, ag), (ag, ex)):
        for k in range(11):
            add(base(ARROWS, dot=lerp(seg[0], seg[1], k / 10),
                     caption="the secret leaves the box", cap_color=RED), 60)
    add(base(ARROWS, dot=ex, caption="EXFILTRATED", cap_color=RED, lit=("agent", "exfil")), 1400)

    add(card(["No server was hacked.",
              "Each tool did its job — the agent's authority was BORROWED.", "",
              "= cross-server confused deputy"],
             [WHITE, DIM, "", AMBER]), 2600)
    add(card(["Renfield PROVES it", "by watching the canary secret leave over HTTP,", "",
              "then computes the MINIMAL FIX that kills every chain."],
             [GREEN, WHITE, "", GREEN]), 2600)
    add(card(["github.com/SYCO7/renfield", "", "find  -  prove  -  fix"],
             ["big", "", BLUE]), 2600)

    os.makedirs(OUT, exist_ok=True)
    gif = os.path.join(OUT, "howitworks.gif")
    frames[0].save(gif, save_all=True, append_images=frames[1:], duration=durs,
                   loop=0, optimize=True)
    print(f"wrote {gif} ({len(frames)} frames, {os.path.getsize(gif)//1024} KB)")
    mp4 = os.path.join(OUT, "howitworks.mp4")
    try:
        subprocess.run(["ffmpeg", "-y", "-i", gif, "-movflags", "+faststart",
                        "-pix_fmt", "yuv420p",
                        "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2", mp4],
                       check=True, capture_output=True)
        print(f"wrote {mp4} ({os.path.getsize(mp4)//1024} KB)")
    except Exception as exc:  # noqa: BLE001
        print(f"(mp4 skipped: {exc})")


if __name__ == "__main__":
    build()
