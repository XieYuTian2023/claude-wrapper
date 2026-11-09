#!/usr/bin/env python3
"""Render xterm headless cell evidence into labelled PNG and standalone SVG."""
import argparse
import html
import json
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


PALETTE = ["#000000", "#cd0000", "#00cd00", "#cdcd00", "#0000ee", "#cd00cd", "#00cdcd", "#e5e5e5",
    "#7f7f7f", "#ff0000", "#00ff00", "#ffff00", "#5c5cff", "#ff00ff", "#00ffff", "#ffffff"]


def color(mode, value, default):
    if mode == 50331648:
        return "#" + format(value, "06x")
    if mode in (16777216, 33554432):
        if value < 16:
            return PALETTE[value]
        if value < 232:
            value -= 16
            levels = [0, 95, 135, 175, 215, 255]
            return "#%02x%02x%02x" % (levels[value // 36], levels[(value // 6) % 6], levels[value % 6])
        return "#%02x%02x%02x" % ((8 + (value - 232) * 10,) * 3)
    return default


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="output basename without extension")
    args = parser.parse_args()
    record = json.loads(args.input.read_text())
    width, height = record["columns"], record["rows"]
    cell_width, cell_height, margin, label_height = 10, 21, 20, 55
    full_width, full_height = width * cell_width + margin * 2, height * cell_height + label_height + margin
    normal = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 16, index=0)
    bold = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", 16, index=1)
    cjk = ImageFont.truetype("/System/Library/Fonts/Hiragino Sans GB.ttc", 16, index=0)
    caption = ImageFont.truetype("/System/Library/Fonts/Hiragino Sans GB.ttc", 15, index=0)
    image = Image.new("RGB", (full_width, full_height), "#0c0e11")
    draw = ImageDraw.Draw(image)
    title = f"PTY 输出渲染 · {width} × {height} · 不是 Terminal 窗口截图"
    draw.text((margin, 18), title, font=caption, fill="#c5cbd4")
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{full_width}" height="{full_height}" viewBox="0 0 {full_width} {full_height}">',
        f'<title>{html.escape(title)}</title>',
        '<desc>Interpreted from captured PTY bytes using xterm headless. Every glyph is positioned by its captured cell coordinate; no application UI is invented.</desc>',
        f'<rect width="{full_width}" height="{full_height}" fill="#0c0e11"/>',
        f'<text x="{margin}" y="33" fill="#c5cbd4" font-family="Hiragino Sans GB,sans-serif" font-size="15">{html.escape(title)}</text>']
    malformed_wide = []
    replacements = 0
    for y, row in enumerate(record["cells"]):
        for x, cell in enumerate(row):
            foreground = color(cell["fgMode"], cell["fg"], "#e3e6eb")
            background = color(cell["bgMode"], cell["bg"], "#121418")
            if cell["inverse"]:
                foreground, background = background, foreground
            left, top = margin + x * cell_width, label_height + y * cell_height
            draw.rectangle((left, top, left + cell_width - 1, top + cell_height - 1), fill=background)
            svg.append(f'<rect x="{left}" y="{top}" width="{cell_width}" height="{cell_height}" fill="{background}"/>')
            chars = cell["chars"]
            if cell["width"] == 2 and (x + 1 >= width or row[x + 1]["width"] != 0):
                malformed_wide.append([y, x])
            replacements += chars.count("\ufffd")
    # Backgrounds are painted before glyphs so a wide continuation never erases
    # the preceding CJK character's right half.
    for y, row in enumerate(record["cells"]):
        for x, cell in enumerate(row):
            chars = cell["chars"]
            if not chars or cell["width"] == 0:
                continue
            foreground = color(cell["bgMode"], cell["bg"], "#121418") if cell["inverse"] else color(cell["fgMode"], cell["fg"], "#e3e6eb")
            if cell["dim"]:
                foreground = "#" + "".join(format(int(foreground[index:index + 2], 16) // 2, "02x") for index in (1, 3, 5))
            font = cjk if any(ord(character) >= 0x2e80 for character in chars) else bold if cell["bold"] else normal
            left = margin + x * cell_width + max(0, (cell["width"] * cell_width - draw.textlength(chars, font=font)) / 2)
            baseline = label_height + y * cell_height + 16
            draw.text((left, baseline), chars, font=font, fill=foreground, anchor="ls")
            if cell["underline"]:
                draw.line((left, baseline + 2, left + cell["width"] * cell_width, baseline + 2), fill=foreground)
            family = "Hiragino Sans GB,sans-serif" if font is cjk else "Menlo,monospace"
            weight = ' font-weight="bold"' if cell["bold"] else ""
            svg.append(f'<text x="{left:.3f}" y="{baseline}" fill="{foreground}" font-family="{family}" font-size="16"{weight}>{html.escape(chars)}</text>')
    svg.append("</svg>")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    image.save(args.out.with_suffix(".png"))
    args.out.with_suffix(".svg").write_text("\n".join(svg) + "\n")
    args.out.with_suffix(".txt").write_text("\n".join(record["text"]) + "\n")
    checks = {"kind": record["kind"], "columns": width, "rows": height,
        "sourceSha256": record["sourceSha256"], "snapshotByteOffset": record["snapshotByteOffset"],
        "interpreter": record["interpreter"], "interpreterVersion": record["interpreterVersion"],
        "wide_cells_have_continuations": not malformed_wide, "malformed_wide_cells": malformed_wide,
        "replacement_characters": replacements,
        "font": "Menlo 16 px + Hiragino Sans GB 16 px; fixed 10x21 px cell grid",
        "limitation": "software PTY rendering; font metrics and glyph appearance can differ from Terminal.app"}
    args.out.with_suffix(".render.json").write_text(json.dumps(checks, indent=2) + "\n")
    print(json.dumps(checks))


if __name__ == "__main__":
    main()
