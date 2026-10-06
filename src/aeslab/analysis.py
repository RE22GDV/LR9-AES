"""Порівняння режимів: властивості, поширення помилок, лавинний ефект."""

from __future__ import annotations

import random

from . import modes
from .aes import AES

# Властивості режимів (SP 800-38A, 38D) для таблиці порівняння.
PROPERTIES = {
    #        доповнення, IV/nonce, паралельне шифр., паралельне розшифр., довільний доступ, цілісність
    "ECB":  ("так", "немає", "так", "так", "так", "ні"),
    "CBC":  ("так", "16 Б, непередбачуваний", "ні", "так", "так", "ні"),
    "CFB8": ("ні", "16 Б, унікальний", "ні", "так", "ні", "ні"),
    "CFB":  ("ні", "16 Б, унікальний", "ні", "так", "так", "ні"),
    "OFB":  ("ні", "16 Б, унікальний", "ні", "ні", "ні", "ні"),
    "CTR":  ("ні", "16 Б, унікальний", "так", "так", "так", "ні"),
    "CTS":  ("ні (≥ 16 Б)", "16 Б, непередбачуваний", "ні", "так", "так", "ні"),
    "GCM":  ("ні", "12 Б, унікальний", "так", "так", "так", "так"),
}
PROPERTY_NAMES = ("Доповнення", "IV / nonce", "Паралельне шифрування",
                  "Паралельне розшифрування", "Довільний доступ", "Цілісність")


def hamming(a, b) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def flip_bit(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(out)


# --- лавинний ефект -----------------------------------------------------------

def avalanche_by_round(trials: int, rng: random.Random, what: str = "plaintext",
                       key_len: int = 16) -> list[float]:
    """Середня кількість відмінних бітів стану після кожного раунду.

    ``what="plaintext"`` — пари відкритих текстів, що різняться одним
    бітом; ``what="key"`` — пари ключів, що різняться одним бітом.
    """
    sums = None
    for _ in range(trials):
        key = rng.randbytes(key_len)
        block = rng.randbytes(16)
        if what == "plaintext":
            a, b = AES(key).trace(block), AES(key).trace(flip_bit(block, rng.randrange(128)))
        else:
            other = flip_bit(key, rng.randrange(8 * key_len))
            a, b = AES(key).trace(block), AES(other).trace(block)
        dist = [hamming(x, y) for x, y in zip(a, b)]
        sums = dist if sums is None else [s + d for s, d in zip(sums, dist)]
    return [s / trials for s in sums]


# --- поширення помилки ------------------------------------------------------------

def error_propagation(mode: str, key: bytes, iv: bytes, message: bytes, bit: int):
    """Що отримає одержувач, якщо в шифротексті інвертовано один біт.

    Повертає список кількостей хибних бітів по байтах відкритого тексту
    або рядок "rejected", якщо режим виявив зміну (GCM), чи "padding",
    якщо зіпсувалося доповнення й розшифрування не вдалося.
    """
    cipher = AES(key)
    ct = modes.encrypt(mode, cipher, iv, message)
    damaged = flip_bit(ct, bit)
    try:
        got = modes.decrypt(mode, cipher, iv, damaged)
    except modes.AuthenticationError:
        return "rejected"
    except modes.PaddingError:
        return "padding"
    return [bin(x ^ y).count("1") for x, y in zip(got, message)]


# --- довжина шифротексту ---------------------------------------------------------

def transmitted_length(mode: str, n: int) -> int | None:
    """Скільки байтів треба передати для повідомлення з n байтів
    (разом з IV/nonce і тегом). None — режим не застосовний."""
    iv = modes.MODE_INFO[mode]["iv"]
    if mode in ("ECB", "CBC"):
        return iv + (n // 16 + 1) * 16
    if mode == "CTS":
        return iv + n if n >= 16 else None
    if mode == "GCM":
        return iv + n + 16
    return iv + n


# --- зображення -------------------------------------------------------------------

def encrypt_pixels(mode: str, cipher, iv: bytes, pixels: bytes) -> bytes:
    """Зашифрувати пікселі й обрізати результат до розміру зображення."""
    if mode in ("ECB", "CBC"):
        body = pixels[:len(pixels) - len(pixels) % 16]
        enc = (modes.ecb_encrypt(cipher, body, pad=False) if mode == "ECB"
               else modes.cbc_encrypt(cipher, iv, body, pad=False))
        return enc + pixels[len(body):]
    return modes.encrypt(mode, cipher, iv, pixels)[:len(pixels)]


def repeated_blocks(data: bytes) -> tuple[int, int]:
    """(кількість блоків, кількість різних блоків) — міра «видимості» шаблонів."""
    blocks = [data[i:i + 16] for i in range(0, len(data) - len(data) % 16, 16)]
    return len(blocks), len(set(blocks))


# --- властивості S-блоку (критерії, за якими його обрано) ---------------------------

def sbox_ddt(sbox=None) -> list[list[int]]:
    """Таблиця різниць: DDT[a][b] = #{x : S(x) ⊕ S(x ⊕ a) = b}."""
    from .aes import SBOX
    s = sbox or SBOX
    table = [[0] * 256 for _ in range(256)]
    for a in range(256):
        row = table[a]
        for x in range(256):
            row[s[x] ^ s[x ^ a]] += 1
    return table


def _walsh(f: list[int]) -> list[int]:
    """Швидке перетворення Уолша — Адамара для ±1-послідовності довжини 256."""
    w = list(f)
    h = 1
    while h < len(w):
        for i in range(0, len(w), 2 * h):
            for j in range(i, i + h):
                a, b = w[j], w[j + h]
                w[j], w[j + h] = a + b, a - b
        h *= 2
    return w


def sbox_linear_bias(sbox=None) -> list[list[int]]:
    """LAT[a][b] = #{x : a·x = b·S(x)} − 128 (через перетворення Уолша)."""
    from .aes import SBOX
    s = sbox or SBOX
    lat = [[0] * 256 for _ in range(256)]
    for b in range(256):
        f = [1 - 2 * (bin(b & s[x]).count("1") & 1) for x in range(256)]
        w = _walsh(f)
        for a in range(256):
            lat[a][b] = w[a] // 2
    return lat


def _anf_degree(bits: list[int]) -> int:
    """Алгебраїчний степінь булевої функції 8 змінних (перетворення Мебіуса)."""
    c = list(bits)
    for i in range(8):
        step = 1 << i
        for x in range(256):
            if x & step:
                c[x] ^= c[x ^ step]
    return max((bin(x).count("1") for x in range(256) if c[x]), default=0)


def sbox_properties(sbox=None) -> dict:
    from .aes import SBOX
    s = sbox or SBOX
    ddt = sbox_ddt(s)
    lat = sbox_linear_bias(s)
    max_ddt = max(ddt[a][b] for a in range(1, 256) for b in range(256))
    max_bias = max(abs(lat[a][b]) for a in range(256) for b in range(1, 256))
    degree = min(_anf_degree([(s[x] >> k) & 1 for x in range(256)]) for k in range(8))
    hist = {}
    for a in range(1, 256):
        for b in range(256):
            hist[ddt[a][b]] = hist.get(ddt[a][b], 0) + 1
    return {
        "differential_uniformity": max_ddt,
        "max_differential_probability": max_ddt / 256,
        "max_linear_bias": max_bias,
        "nonlinearity": 128 - max_bias,
        "algebraic_degree": degree,
        "fixed_points": sum(s[x] == x for x in range(256)),
        "opposite_fixed_points": sum(s[x] == x ^ 0xFF for x in range(256)),
        "ddt_histogram": dict(sorted(hist.items())),
    }


# --- строгий лавинний критерій --------------------------------------------------

def sac_matrices(trials: int, rng: random.Random, rounds=(1, 2, 3, 10)) -> dict[int, list[list[float]]]:
    """P(вихідний біт j змінився | інвертовано вхідний біт i) після кожного з ``rounds``.

    Ідеальний шифр дає 0,5 у кожній клітинці (строгий лавинний критерій).
    """
    counts = {r: [[0] * 128 for _ in range(128)] for r in rounds}
    for _ in range(trials):
        key = rng.randbytes(16)
        cipher = AES(key)
        block = rng.randbytes(16)
        base = cipher.trace(block)
        base_bits = {r: int.from_bytes(bytes(base[r]), "big") for r in rounds}
        for i in range(128):
            other = cipher.trace(flip_bit(block, i))
            for r in rounds:
                diff = base_bits[r] ^ int.from_bytes(bytes(other[r]), "big")
                row = counts[r][i]
                while diff:
                    low = diff & -diff
                    row[127 - (low.bit_length() - 1)] += 1
                    diff ^= low
    return {r: [[v / trials for v in row] for row in m] for r, m in counts.items()}


# --- статистика шифротексту ---------------------------------------------------------

def byte_statistics(data: bytes) -> dict:
    """Ентропія Шеннона (біт/байт), χ² щодо рівномірного розподілу, різні блоки."""
    import math
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = -sum(c / n * math.log2(c / n) for c in counts if c)
    expected = n / 256
    chi2 = sum((c - expected) ** 2 / expected for c in counts)
    total, distinct = repeated_blocks(data)
    entropy = 0.0 if entropy <= 0 else entropy          # без «−0,0» для однакових байтів
    return {"entropy": entropy, "chi2": chi2, "blocks": total, "distinct_blocks": distinct}
