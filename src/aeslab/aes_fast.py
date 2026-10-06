"""Таблична реалізація AES (T-таблиці), друга версія шифру.

Раунд AES — це SubBytes, ShiftRows і MixColumns, які для кожного байта
стану можна заздалегідь об'єднати в одну 32-бітову таблицю. Тоді раунд
зводиться до 16 звертань до таблиць і XOR із раундовим ключем. Для
розшифрування використано «еквівалентний обернений шифр» FIPS-197 §5.3.5:
до раундових ключів застосовано InvMixColumns.

З модуля ``aes`` взято лише S-блок і розклад ключа; раунди шифрування й
розшифрування реалізовано окремо, тож дві реалізації перевіряють одна одну.
"""

from __future__ import annotations

from .aes import INV_SBOX, KEY_SIZES, SBOX, expand_key, gmul


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _word(b0: int, b1: int, b2: int, b3: int) -> int:
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3


TE0 = [_word(gmul(s, 2), s, s, gmul(s, 3)) for s in SBOX]
TE1 = [_rotr(t, 8) for t in TE0]
TE2 = [_rotr(t, 16) for t in TE0]
TE3 = [_rotr(t, 24) for t in TE0]
TD0 = [_word(gmul(s, 14), gmul(s, 9), gmul(s, 13), gmul(s, 11)) for s in INV_SBOX]
TD1 = [_rotr(t, 8) for t in TD0]
TD2 = [_rotr(t, 16) for t in TD0]
TD3 = [_rotr(t, 24) for t in TD0]
# InvMixColumns для байта b — це TD*[SBOX[b]], бо INV_SBOX[SBOX[b]] = b.
_IMC = [TD0[SBOX[b]] for b in range(256)]


def _inv_mix_word(w: int) -> int:
    return (_IMC[w >> 24] ^ _rotr(_IMC[(w >> 16) & 0xFF], 8)
            ^ _rotr(_IMC[(w >> 8) & 0xFF], 16) ^ _rotr(_IMC[w & 0xFF], 24))


class FastAES:
    """Той самий AES, але на 32-бітових словах і T-таблицях."""

    block_size = 16

    def __init__(self, key: bytes):
        if len(key) not in KEY_SIZES:
            raise ValueError("ключ AES має 16, 24 або 32 байти")
        self.key = bytes(key)
        self.rounds = KEY_SIZES[len(key)]
        keys = expand_key(self.key)
        self.ek = [[_word(*k[4 * c:4 * c + 4]) for c in range(4)] for k in keys]
        dk = [self.ek[self.rounds]]
        for r in range(self.rounds - 1, 0, -1):
            dk.append([_inv_mix_word(w) for w in self.ek[r]])
        dk.append(self.ek[0])
        self.dk = dk

    def encrypt_block(self, block: bytes) -> bytes:
        ek = self.ek
        k = ek[0]
        s0 = int.from_bytes(block[0:4], "big") ^ k[0]
        s1 = int.from_bytes(block[4:8], "big") ^ k[1]
        s2 = int.from_bytes(block[8:12], "big") ^ k[2]
        s3 = int.from_bytes(block[12:16], "big") ^ k[3]
        for r in range(1, self.rounds):
            k = ek[r]
            t0 = TE0[s0 >> 24] ^ TE1[(s1 >> 16) & 255] ^ TE2[(s2 >> 8) & 255] ^ TE3[s3 & 255] ^ k[0]
            t1 = TE0[s1 >> 24] ^ TE1[(s2 >> 16) & 255] ^ TE2[(s3 >> 8) & 255] ^ TE3[s0 & 255] ^ k[1]
            t2 = TE0[s2 >> 24] ^ TE1[(s3 >> 16) & 255] ^ TE2[(s0 >> 8) & 255] ^ TE3[s1 & 255] ^ k[2]
            t3 = TE0[s3 >> 24] ^ TE1[(s0 >> 16) & 255] ^ TE2[(s1 >> 8) & 255] ^ TE3[s2 & 255] ^ k[3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        k = ek[self.rounds]
        S = SBOX
        out = bytearray(16)
        for i, (a, b, c, d) in enumerate(((s0, s1, s2, s3), (s1, s2, s3, s0),
                                          (s2, s3, s0, s1), (s3, s0, s1, s2))):
            w = _word(S[a >> 24], S[(b >> 16) & 255], S[(c >> 8) & 255], S[d & 255]) ^ k[i]
            out[4 * i:4 * i + 4] = w.to_bytes(4, "big")
        return bytes(out)

    def decrypt_block(self, block: bytes) -> bytes:
        dk = self.dk
        k = dk[0]
        s0 = int.from_bytes(block[0:4], "big") ^ k[0]
        s1 = int.from_bytes(block[4:8], "big") ^ k[1]
        s2 = int.from_bytes(block[8:12], "big") ^ k[2]
        s3 = int.from_bytes(block[12:16], "big") ^ k[3]
        for r in range(1, self.rounds):
            k = dk[r]
            t0 = TD0[s0 >> 24] ^ TD1[(s3 >> 16) & 255] ^ TD2[(s2 >> 8) & 255] ^ TD3[s1 & 255] ^ k[0]
            t1 = TD0[s1 >> 24] ^ TD1[(s0 >> 16) & 255] ^ TD2[(s3 >> 8) & 255] ^ TD3[s2 & 255] ^ k[1]
            t2 = TD0[s2 >> 24] ^ TD1[(s1 >> 16) & 255] ^ TD2[(s0 >> 8) & 255] ^ TD3[s3 & 255] ^ k[2]
            t3 = TD0[s3 >> 24] ^ TD1[(s2 >> 16) & 255] ^ TD2[(s1 >> 8) & 255] ^ TD3[s0 & 255] ^ k[3]
            s0, s1, s2, s3 = t0, t1, t2, t3
        k = dk[self.rounds]
        S = INV_SBOX
        out = bytearray(16)
        for i, (a, b, c, d) in enumerate(((s0, s3, s2, s1), (s1, s0, s3, s2),
                                          (s2, s1, s0, s3), (s3, s2, s1, s0))):
            w = _word(S[a >> 24], S[(b >> 16) & 255], S[(c >> 8) & 255], S[d & 255]) ^ k[i]
            out[4 * i:4 * i + 4] = w.to_bytes(4, "big")
        return bytes(out)
