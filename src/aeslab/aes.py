"""Еталонна реалізація блочного шифру AES (FIPS-197) «як у стандарті».

Стан — 16 байтів у порядку стовпців: байт ``state[r + 4c]`` стоїть у
рядку r і стовпці c. Кожен раунд складається з чотирьох перетворень:
SubBytes, ShiftRows, MixColumns, AddRoundKey (в останньому раунді без
MixColumns). Таблиці S-блоку не вписані вручну, а обчислюються з
визначення: обернений елемент у GF(2^8) і афінне перетворення.

Ця версія навмисно проста й повільна; швидка табличнa — ``aes_fast``.
"""

from __future__ import annotations

BLOCK = 16
KEY_SIZES = {16: 10, 24: 12, 32: 14}        # байти ключа → кількість раундів


# --- поле GF(2^8) з многочленом x^8 + x^4 + x^3 + x + 1 (0x11B) ----------------

def xtime(a: int) -> int:
    """Множення на x (тобто на 2) у полі AES."""
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def gmul(a: int, b: int) -> int:
    """Множення в GF(2^8) зсувами й додаваннями."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def _build_sbox() -> tuple[list[int], list[int]]:
    # Логарифми за твірним елементом 3 дають обернені елементи без перебору.
    exp, log = [0] * 255, [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x = gmul(x, 3)
    sbox, inv = [0] * 256, [0] * 256
    for a in range(256):
        b = 0 if a == 0 else exp[(255 - log[a]) % 255]
        # афінне перетворення: b ⊕ rot(b,1) ⊕ rot(b,2) ⊕ rot(b,3) ⊕ rot(b,4) ⊕ 0x63
        s = b
        for shift in range(1, 5):
            s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
        s ^= 0x63
        sbox[a] = s
        inv[s] = a
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()

RCON = [0x01]
for _ in range(13):
    RCON.append(xtime(RCON[-1]))


# --- розклад ключа ----------------------------------------------------------

def expand_key(key: bytes) -> list[list[int]]:
    """Раундові ключі: Nr + 1 блоків по 16 байтів (порядок стовпців)."""
    nk = len(key) // 4
    if len(key) not in KEY_SIZES:
        raise ValueError("ключ AES має 16, 24 або 32 байти")
    nr = KEY_SIZES[len(key)]
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                      # RotWord
            temp = [SBOX[b] for b in temp]                   # SubWord
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(nr + 1)]


# --- раундові перетворення ---------------------------------------------------

def sub_bytes(s: list[int]) -> list[int]:
    return [SBOX[b] for b in s]


def inv_sub_bytes(s: list[int]) -> list[int]:
    return [INV_SBOX[b] for b in s]


def shift_rows(s: list[int]) -> list[int]:
    # рядок r зсувається ліворуч на r позицій
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(s: list[int]) -> list[int]:
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def mix_columns(s: list[int]) -> list[int]:
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3,
                a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3,
                a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3,
                xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)]
    return out


def inv_mix_columns(s: list[int]) -> list[int]:
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9),
                gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13),
                gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11),
                gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)]
    return out


def add_round_key(s: list[int], k: list[int]) -> list[int]:
    return [a ^ b for a, b in zip(s, k)]


class AES:
    """Блочний шифр AES-128/192/256: один блок 16 байтів за виклик."""

    block_size = BLOCK

    def __init__(self, key: bytes):
        self.key = bytes(key)
        self.rounds = KEY_SIZES.get(len(key), 0)
        self.round_keys = expand_key(self.key)

    def encrypt_block(self, block: bytes) -> bytes:
        return bytes(self.trace(block)[-1])

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK:
            raise ValueError("блок AES має 16 байтів")
        s = add_round_key(list(block), self.round_keys[self.rounds])
        for r in range(self.rounds - 1, 0, -1):
            s = inv_shift_rows(s)
            s = inv_sub_bytes(s)
            s = add_round_key(s, self.round_keys[r])
            s = inv_mix_columns(s)
        s = inv_sub_bytes(inv_shift_rows(s))
        return bytes(add_round_key(s, self.round_keys[0]))

    def trace(self, block: bytes) -> list[list[int]]:
        """Стан після початкового AddRoundKey і після кожного раунду."""
        if len(block) != BLOCK:
            raise ValueError("блок AES має 16 байтів")
        s = add_round_key(list(block), self.round_keys[0])
        states = [s]
        for r in range(1, self.rounds + 1):
            s = shift_rows(sub_bytes(s))
            if r != self.rounds:
                s = mix_columns(s)
            s = add_round_key(s, self.round_keys[r])
            states.append(s)
        return states
