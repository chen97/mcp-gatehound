#!/usr/bin/env python3
"""Generate the application icons from one vector description.

Run from the repository root:

    python3 scripts/make-icons.py

Writes PNG, ICO and ICNS files into crates/gatehound-app/icons/. The mark is a portcullis —
a gate — drawn geometrically so it survives being 16 pixels wide in a menubar. Everything is
supersampled 4x and box-filtered, which is all the antialiasing a shape this simple needs.

Only the standard library is used, so this runs anywhere the rest of the toolchain does.
"""

import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "crates", "gatehound-app", "icons")

AMBER = (0xF2, 0xC1, 0x4E)
INK = (0x1A, 0x14, 0x05)
SS = 4  # supersampling factor


def rounded_rect(x, y, w, h, r):
    """Predicate: is (x, y) inside a rounded rectangle at the origin of size w x h?"""
    if x < 0 or y < 0 or x >= w or y >= h:
        return False
    cx = min(max(x, r), w - r)
    cy = min(max(y, r), h - r)
    dx, dy = x - cx, y - cy
    return dx * dx + dy * dy <= r * r or (r <= x <= w - r) or (r <= y <= h - r)


def portcullis(x, y, size):
    """Predicate: is (x, y) inside the gate glyph drawn on a `size` x `size` canvas?"""
    m = size * 0.22          # margin
    inner = size - 2 * m
    bar = size * 0.075       # bar thickness
    if not (m <= x <= size - m and m <= y <= size - m):
        return False
    # A thick lintel across the top.
    if y <= m + bar * 1.5:
        return True
    # One crossbar partway down.
    cy = m + inner * 0.5
    if abs(y - cy) <= bar / 2:
        return True
    # Three uprights, running free to the bottom like portcullis teeth.
    for i in range(3):
        cx = m + inner * (0.5 + i) / 3
        if abs(x - cx) <= bar / 2:
            return True
    return False


def render(size, background=True):
    """Return RGBA bytes for one icon at `size` pixels."""
    big = size * SS
    radius = big * 0.22
    acc = bytearray(size * size * 4)

    for py in range(size):
        for px in range(size):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    X = px * SS + sx + 0.5
                    Y = py * SS + sy + 0.5
                    inside_bg = background and rounded_rect(X, Y, big, big, radius)
                    inside_fg = portcullis(X, Y, big)
                    if background:
                        if inside_fg:
                            c, alpha = INK, 255
                        elif inside_bg:
                            c, alpha = AMBER, 255
                        else:
                            c, alpha = (0, 0, 0), 0
                    else:
                        # Template icon: the glyph in black, everything else transparent.
                        c, alpha = (INK if inside_fg else (0, 0, 0)), (255 if inside_fg else 0)
                    r += c[0] * alpha
                    g += c[1] * alpha
                    b += c[2] * alpha
                    a += alpha
            n = SS * SS
            i = (py * size + px) * 4
            if a == 0:
                acc[i : i + 4] = bytes(4)
            else:
                # Un-premultiply so the averaged colour is right at the edges.
                acc[i + 0] = min(255, r // a)
                acc[i + 1] = min(255, g // a)
                acc[i + 2] = min(255, b // a)
                acc[i + 3] = a // n
    return bytes(acc)


def png(size, rgba):
    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + rgba[y * size * 4 : (y + 1) * size * 4] for y in range(size))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


def ico(images):
    """Windows .ico with PNG-compressed entries (supported since Vista)."""
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    entries, payloads = b"", b""
    for size, blob in images:
        entries += struct.pack(
            "<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset
        )
        payloads += blob
        offset += len(blob)
    return header + entries + payloads


def icns(entries):
    """macOS .icns: a magic word, a length, then typed chunks of PNG."""
    body = b""
    for kind, blob in entries:
        body += kind + struct.pack(">I", len(blob) + 8) + blob
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def main():
    os.makedirs(OUT, exist_ok=True)
    sizes = [16, 32, 48, 64, 128, 256, 512, 1024]
    blobs = {s: png(s, render(s)) for s in sizes}

    def write(name, data):
        path = os.path.join(OUT, name)
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"{os.path.relpath(path)}  {len(data):,} bytes")

    write("32x32.png", blobs[32])
    write("128x128.png", blobs[128])
    write("128x128@2x.png", blobs[256])
    write("icon.png", blobs[1024])
    write("icon.ico", ico([(s, blobs[s]) for s in (16, 32, 48, 64, 256)]))
    write(
        "icon.icns",
        icns(
            [
                (b"ic11", blobs[32]),    # 16@2x
                (b"ic12", blobs[64]),    # 32@2x
                (b"ic07", blobs[128]),
                (b"ic08", blobs[256]),
                (b"ic09", blobs[512]),
                (b"ic10", blobs[1024]),  # 512@2x
            ]
        ),
    )
    # The menubar icon is a template: macOS recolours it for light and dark menu bars, so it
    # must be a shape in alpha rather than a coloured picture.
    write("tray.png", png(32, render(32, background=False)))
    write("tray@2x.png", png(64, render(64, background=False)))


if __name__ == "__main__":
    main()
