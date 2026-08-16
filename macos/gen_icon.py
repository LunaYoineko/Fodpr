#!/usr/bin/env python3
"""Fodpr Chat の macOS アプリアイコン (1024x1024 PNG) を生成する。

標準ライブラリのみ使用 (外部依存なし)。build.sh から呼ばれ、
生成された PNG は sips / iconutil で .icns に変換される。

Usage: python3 macos/gen_icon.py [output.png]
"""
import struct
import sys
import zlib

W = 1024


def png_chunk(tag, data):
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def write_png(path, width, height, rgba):
    stride = width * 4
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter: none
        raw.extend(rgba[y * stride:(y + 1) * stride])
    png = b"\x89PNG\r\n\x1a\n"
    png += png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
    png += png_chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    png += png_chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


def rounded_rect(x0, y0, x1, y1, r):
    pts = set()
    for y in range(y0, y1 + 1):
        for x in range(x0, x1 + 1):
            cx = min(max(x, x0 + r), x1 - r)
            cy = min(max(y, y0 + r), y1 - r)
            dx, dy = x - cx, y - cy
            if dx * dx + dy * dy <= r * r:
                pts.add((x, y))
    return pts


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "FodprChat.png"

    img = bytearray(W * W * 4)  # 透明で初期化

    def setpx(x, y, r, g, b, a=255):
        i = (y * W + x) * 4
        img[i] = r
        img[i + 1] = g
        img[i + 2] = b
        img[i + 3] = a

    # 背景: 角丸四角 + 青の縦グラデーション
    bg = rounded_rect(24, 24, 1000, 1000, 200)
    for (x, y) in bg:
        t = y / W
        setpx(x, y, int(38 + (66 - 38) * t), int(70 + (105 - 70) * t),
              int(110 + (150 - 110) * t))

    # 吹き出し (チャットバブル)
    bubble = rounded_rect(180, 200, 844, 640, 80)
    for (x, y) in bubble:
        setpx(x, y, 245, 245, 247)

    # 吹き出しの尾 (左下の三角)
    for y in range(641, 821):
        # 頂点 (330,820) から上辺 (400,640)-(540,640) へ広がる
        t = (y - 640) / 180.0
        xl = 400 - (400 - 330) * t
        xr = 540 + (540 - 330) * t
        for x in range(int(xl), int(xr) + 1):
            if 0 <= x < W and 0 <= y < W:
                setpx(x, y, 245, 245, 247)

    # 文字 "F" (5x7 ビットマップ, セル=56px, 280x392)
    f_bitmap = [
        "11111",
        "10000",
        "10000",
        "11110",
        "10000",
        "10000",
        "10000",
    ]
    cell = 56
    ox = 512 - (len(f_bitmap[0]) * cell) // 2  # 中央寄せ
    oy = 420 - (len(f_bitmap) * cell) // 2
    blue = (30, 58, 95)
    for row, line in enumerate(f_bitmap):
        for col, ch in enumerate(line):
            if ch != "1":
                continue
            for yy in range(cell):
                for xx in range(cell):
                    setpx(ox + col * cell + xx, oy + row * cell + yy, *blue)

    write_png(out, W, W, img)
    print(f"wrote {out} ({W}x{W})")


if __name__ == "__main__":
    main()
