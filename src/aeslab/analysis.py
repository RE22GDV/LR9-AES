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
