"""Блочний шифр AES: таблиці, розклад ключа, дві незалежні реалізації."""

from __future__ import annotations

import random

import pytest

from aeslab.aes import AES, INV_SBOX, RCON, SBOX, expand_key, gmul, xtime
from aeslab.aes_fast import FastAES

FIPS = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "8ea2b7ca516745bfeafc49904b496089"),
]
PT = bytes.fromhex("00112233445566778899aabbccddeeff")


def test_sbox_is_a_permutation_with_known_values() -> None:
    assert sorted(SBOX) == list(range(256))
    assert all(INV_SBOX[SBOX[b]] == b for b in range(256))
    assert (SBOX[0x00], SBOX[0x01], SBOX[0x53], SBOX[0xFF]) == (0x63, 0x7C, 0xED, 0x16)
    assert all(SBOX[b] != b and SBOX[b] != b ^ 0xFF for b in range(256))   # немає нерухомих точок


def test_field_arithmetic() -> None:
    assert gmul(0x57, 0x83) == 0xC1                     # приклад FIPS-197 §4.2
    assert xtime(0x57) == 0xAE and xtime(0xAE) == 0x47
    assert RCON[:10] == [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def test_key_expansion_matches_fips_appendix_a() -> None:
    rk = expand_key(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert len(rk) == 11
    assert bytes(rk[1]).hex() == "a0fafe1788542cb123a339392a6c7605"
    assert bytes(rk[10]).hex() == "d014f9a8c9ee2589e13f0cc8b6630ca6"
    assert len(expand_key(bytes(24))) == 13 and len(expand_key(bytes(32))) == 15


@pytest.mark.parametrize("cls", [AES, FastAES])
@pytest.mark.parametrize("key,ct", FIPS)
def test_fips197_appendix_c(cls, key: str, ct: str) -> None:
    cipher = cls(bytes.fromhex(key))
    assert cipher.encrypt_block(PT).hex() == ct
    assert cipher.decrypt_block(bytes.fromhex(ct)) == PT


def test_round_trace_starts_and_ends_correctly() -> None:
    trace = AES(bytes.fromhex(FIPS[0][0])).trace(PT)
    assert len(trace) == 11
    assert bytes(trace[0]).hex() == "00102030405060708090a0b0c0d0e0f0"   # вхід ⊕ K0
    assert bytes(trace[1]).hex() == "89d810e8855ace682d1843d8cb128fe4"   # FIPS-197 C.1, раунд 1
    assert bytes(trace[-1]).hex() == FIPS[0][1]


def test_implementations_agree_on_random_blocks() -> None:
    rng = random.Random(9)
    for _ in range(300):
        key = rng.randbytes(rng.choice([16, 24, 32]))
        block = rng.randbytes(16)
        a, b = AES(key), FastAES(key)
        ct = a.encrypt_block(block)
        assert b.encrypt_block(block) == ct
        assert a.decrypt_block(ct) == b.decrypt_block(ct) == block


def test_matches_openssl() -> None:
    pytest.importorskip("cryptography")
    from aeslab.backends import OpenSSLAES
    rng = random.Random(10)
    for _ in range(200):
        key = rng.randbytes(rng.choice([16, 24, 32]))
        block = rng.randbytes(16)
        assert FastAES(key).encrypt_block(block) == OpenSSLAES(key).encrypt_block(block)


@pytest.mark.parametrize("bad", [b"", bytes(15), bytes(20), bytes(33)])
def test_rejects_wrong_key_length(bad: bytes) -> None:
    with pytest.raises(ValueError):
        AES(bad)
    with pytest.raises(ValueError):
        FastAES(bad)
