"""Демонстраційне зображення з великими однотонними ділянками (без Pillow).

На такому зображенні добре видно, чому ECB розкриває структуру даних:
однакові 16-байтові блоки пікселів дають однакові блоки шифротексту.
"""

from __future__ import annotations

WIDTH, HEIGHT = 192, 128

BACKGROUND = (246, 244, 238)
COLORS = [(42, 120, 214), (235, 104, 52), (27, 175, 122), (40, 40, 44)]

# Літери «A», «E», «S» у сітці 5 × 7 клітинок.
GLYPHS = {
    "A": ["01110", "10001", "10001", "11111", "10001", "10001", "10001"],
    "E": ["11111", "10000", "10000", "11110", "10000", "10000", "11111"],
    "S": ["01111", "10000", "10000", "01110", "00001", "00001", "11110"],
}


def render() -> tuple[int, int, bytes]:
    """(ширина, висота, пікселі RGB по рядках)."""
    px = [list(BACKGROUND) for _ in range(WIDTH * HEIGHT)]

    def put(x, y, color):
        if 0 <= x < WIDTH and 0 <= y < HEIGHT:
            px[y * WIDTH + x] = list(color)

    # кольорові смуги вгорі та внизу
    for y in range(0, 14):
        for x in range(WIDTH):
            put(x, y, COLORS[(x // 48) % 4])
    for y in range(HEIGHT - 14, HEIGHT):
        for x in range(WIDTH):
            put(x, y, COLORS[3 - (x // 48) % 4])
    # великі літери AES
    cell = 7
    left = (WIDTH - 3 * 5 * cell - 2 * cell) // 2
    for i, ch in enumerate("AES"):
        for gy, row in enumerate(GLYPHS[ch]):
            for gx, bit in enumerate(row):
                if bit == "1":
                    for dy in range(cell):
                        for dx in range(cell):
                            put(left + i * 6 * cell + gx * cell + dx, 30 + gy * cell + dy,
                                COLORS[i])
    # коло під літерами
    cx, cy, r = WIDTH // 2, 100, 9
    for y in range(cy - r, cy + r + 1):
        for x in range(cx - r, cx + r + 1):
            if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:
                put(x, y, COLORS[3])
    return WIDTH, HEIGHT, bytes(v for p in px for v in p)


def to_ppm(width: int, height: int, rgb: bytes) -> bytes:
    return b"P6\n%d %d\n255\n" % (width, height) + rgb


def from_ppm(data: bytes) -> tuple[int, int, bytes]:
    """Розібрати двійковий PPM (P6, 8 бітів на канал)."""
    parts, pos = [], 0
    while len(parts) < 4:
        while data[pos:pos + 1].isspace():
            pos += 1
        if data[pos:pos + 1] == b"#":
            pos = data.index(b"\n", pos) + 1
            continue
        end = pos
        while not data[end:end + 1].isspace():
            end += 1
        parts.append(data[pos:end])
        pos = end
    if parts[0] != b"P6" or parts[3] != b"255":
        raise ValueError("підтримано лише двійковий PPM (P6, 255)")
    width, height = int(parts[1]), int(parts[2])
    pixels = data[pos + 1:pos + 1 + 3 * width * height]
    return width, height, pixels
