"""Режими шифрування: офіційні вектори, зворотність, властивості."""

from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from aeslab import modes
from aeslab.aes import AES
from aeslab.aes_fast import FastAES
from aeslab.backends import IMPLEMENTATIONS
from aeslab.cli import check_vector

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests" / "vectors.json").read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("name", list(IMPLEMENTATIONS))
@pytest.mark.parametrize("vector", VECTORS, ids=[v["source"] for v in VECTORS])
def test_official_vectors(vector: dict, name: str) -> None:
    assert check_vector(vector, IMPLEMENTATIONS[name])


def test_vector_set_covers_every_mode() -> None:
    assert {v["mode"] for v in VECTORS} == {"BLOCK", "ECB", "CBC", "CFB8", "CFB", "OFB", "CTR",
                                            "GCM", "CTS"}


@pytest.mark.parametrize("mode", modes.MODES)
def test_round_trip_for_all_lengths(mode: str) -> None:
    rng = random.Random(hash(mode) & 0xFFFF)
    for n in range(0, 70):
        if mode == "CTS" and n < 16:
            continue
        key = rng.randbytes(rng.choice([16, 24, 32]))
        iv = rng.randbytes(modes.MODE_INFO[mode]["iv"])
        data = rng.randbytes(n)
        ct = modes.encrypt(mode, FastAES(key), iv, data)
        assert modes.decrypt(mode, AES(key), iv, ct) == data


def test_ciphertext_lengths() -> None:
    key, iv = bytes(16), bytes(16)
    c = FastAES(key)
    for n in (0, 1, 15, 16, 17, 33):
        assert len(modes.encrypt("ECB", c, b"", bytes(n))) == (n // 16 + 1) * 16
        assert len(modes.encrypt("CTR", c, iv, bytes(n))) == n
        assert len(modes.encrypt("GCM", c, iv[:12], bytes(n))) == n + 16
        if n >= 16:
            assert len(modes.encrypt("CTS", c, iv, bytes(n))) == n


def test_ecb_repeats_blocks_other_modes_do_not() -> None:
    c, iv = FastAES(bytes(range(16))), bytes(16)
    data = b"A" * 64
    ecb = modes.encrypt("ECB", c, b"", data)
    assert len({ecb[i:i + 16] for i in range(0, 64, 16)}) == 1
    for mode in ("CBC", "CFB", "OFB", "CTR"):
        ct = modes.encrypt(mode, c, iv, data)
        assert len({ct[i:i + 16] for i in range(0, 64, 16)}) == 4


def test_ctr_random_access() -> None:
    c, ctr = FastAES(bytes(16)), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    data = bytes(range(64))
    ct = modes.ctr_crypt(c, ctr, data)
    for i in range(4):
        assert modes.ctr_block(c, ctr, ct[16 * i:16 * i + 16], i) == data[16 * i:16 * i + 16]


def test_ctr_counter_wraps_around() -> None:
    c = FastAES(bytes(16))
    two = modes.ctr_keystream(c, b"\xff" * 16, 32)
    assert two[16:] == c.encrypt_block(bytes(16))


def test_stream_modes_are_their_own_inverse() -> None:
    c, iv = FastAES(bytes(16)), bytes(range(16))
    data = b"stream cipher property"
    for f in (modes.ofb_crypt, modes.ctr_crypt):
        assert f(c, iv, f(c, iv, data)) == data


def test_padding_validation() -> None:
    assert modes.pkcs7_pad(b"") == b"\x10" * 16
    assert modes.pkcs7_unpad(b"abc" + b"\x0d" * 13) == b"abc"
    for bad in (b"", bytes(15), bytes(15) + b"\x00", bytes(14) + b"\x01\x02", bytes(16) + b"\x11" * 16):
        with pytest.raises(modes.PaddingError):
            modes.pkcs7_unpad(bad)


def test_gcm_detects_any_change() -> None:
    c, nonce, aad = FastAES(bytes(range(16))), bytes(12), b"header"
    data = b"PAY 100 UAH to account 42"
    ct = modes.encrypt("GCM", c, nonce, data, aad)
    for bit in range(0, 8 * len(ct), 7):
        damaged = bytearray(ct)
        damaged[bit // 8] ^= 1 << (bit % 8)
        with pytest.raises(modes.AuthenticationError):
            modes.decrypt("GCM", c, nonce, bytes(damaged), aad)
    with pytest.raises(modes.AuthenticationError):
        modes.decrypt("GCM", c, nonce, ct, b"Header")
    with pytest.raises(modes.AuthenticationError):
        modes.decrypt("GCM", c, bytes(11) + b"\x01", ct, aad)


def test_gcm_multiplication_properties() -> None:
    rng = random.Random(3)
    one = 1 << 127                                     # одиниця поля в порядку бітів GCM
    for _ in range(50):
        a, b, c = (rng.getrandbits(128) for _ in range(3))
        assert modes.gf128_mul(a, one) == a
        assert modes.gf128_mul(a, b) == modes.gf128_mul(b, a)
        assert modes.gf128_mul(a, b ^ c) == modes.gf128_mul(a, b) ^ modes.gf128_mul(a, c)
        assert modes.GHash(b).mul_h(a) == modes.gf128_mul(a, b)


def test_iv_length_is_checked() -> None:
    c = FastAES(bytes(16))
    for mode in ("CBC", "CFB", "OFB", "CTR", "CTS"):
        with pytest.raises(ValueError):
            modes.encrypt(mode, c, bytes(12), bytes(32))
    with pytest.raises(ValueError):
        modes.encrypt("CTS", c, bytes(16), bytes(15))


def test_against_openssl_random() -> None:
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        from cryptography.hazmat.decrepit.ciphers import modes as old
    except ImportError:                                # старіші версії бібліотеки
        from cryptography.hazmat.primitives.ciphers import modes as old
    from cryptography.hazmat.primitives.ciphers import modes as cm

    factories = {"CBC": cm.CBC, "CTR": cm.CTR, "OFB": old.OFB, "CFB": old.CFB, "CFB8": old.CFB8}
    rng = random.Random(4)
    for _ in range(100):
        key = rng.randbytes(rng.choice([16, 24, 32]))
        iv = rng.randbytes(16)
        data = rng.randbytes(rng.randrange(70))
        for mode, factory in factories.items():
            enc = Cipher(algorithms.AES(key), factory(iv)).encryptor()
            ref = enc.update(modes.pkcs7_pad(data) if mode == "CBC" else data) + enc.finalize()
            assert modes.encrypt(mode, FastAES(key), iv, data) == ref, mode
        nonce, aad = rng.randbytes(12), rng.randbytes(rng.randrange(20))
        assert modes.encrypt("GCM", FastAES(key), nonce, data, aad) == AESGCM(key).encrypt(nonce, data, aad)
