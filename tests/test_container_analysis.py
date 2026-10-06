"""Формат файлів .aeslab і функції порівняння режимів."""

from __future__ import annotations

import random

import pytest

from aeslab import analysis, container, demo_image, modes


@pytest.mark.parametrize("mode", modes.MODES)
def test_seal_and_open_every_mode(mode: str) -> None:
    data = b"Lab 9: AES file container " * 3
    blob = container.seal(data, "пароль", mode, 16, iterations=1000)
    out, header = container.open_sealed(blob, "пароль")
    assert out == data and header.mode == mode and header.key_len == 16


@pytest.mark.parametrize("mode", ["GCM", "CBC", "CTR", "ECB"])
def test_wrong_password_and_tampering_are_detected(mode: str) -> None:
    blob = container.seal(b"secret data, 32 bytes long......", "right", mode, 32, iterations=1000)
    with pytest.raises(container.ContainerError):
        container.open_sealed(blob, "wrong")
    for pos in (8, 20, len(blob) // 2, len(blob) - 1):        # заголовок, сіль, тіло, тег
        damaged = bytearray(blob)
        damaged[pos] ^= 0x01
        with pytest.raises(container.ContainerError):
            container.open_sealed(bytes(damaged), "right")


def test_container_rejects_garbage() -> None:
    with pytest.raises(container.ContainerError):
        container.open_sealed(b"not an aeslab file at all", "x")


def test_salt_and_iv_are_fresh_each_time() -> None:
    a = container.seal(b"same", "pw", "GCM", iterations=1000)
    b = container.seal(b"same", "pw", "GCM", iterations=1000)
    assert a != b


def test_error_propagation_patterns() -> None:
    key, iv, msg = bytes(range(16)), bytes(range(16, 32)), bytes(64)
    bit = 128 + 3                       # біт 3 першого байта другого блоку

    def damaged(mode):
        res = analysis.error_propagation(mode, key, iv[:modes.MODE_INFO[mode]["iv"]], msg, bit)
        return [i for i, v in enumerate(res) if v] if isinstance(res, list) else res

    assert damaged("ECB") == list(range(16, 32))
    assert damaged("CBC") == list(range(16, 32)) + [32]
    assert damaged("CFB") == [16] + list(range(32, 48))
    assert damaged("CFB8") == list(range(16, 33))
    assert damaged("OFB") == damaged("CTR") == [16]
    assert damaged("GCM") == "rejected"
    res = analysis.error_propagation("CTR", key, iv, msg, bit)
    assert sum(res) == 1                # рівно один біт


def test_transmitted_length() -> None:
    assert analysis.transmitted_length("ECB", 0) == 16
    assert analysis.transmitted_length("CBC", 16) == 16 + 32
    assert analysis.transmitted_length("CTR", 5) == 21
    assert analysis.transmitted_length("GCM", 5) == 12 + 5 + 16
    assert analysis.transmitted_length("CTS", 15) is None


def test_avalanche_reaches_half_after_two_rounds() -> None:
    curve = analysis.avalanche_by_round(60, random.Random(1))
    assert curve[0] == 1                # до раундів відрізняється рівно один біт
    assert 8 < curve[1] < 24            # один стовпець: 4 байти по ≈4 біти
    assert all(55 < d < 73 for d in curve[2:])


def test_diffusion_by_bytes_one_column_then_whole_state() -> None:
    from aeslab.aes import AES
    rng = random.Random(2)
    for _ in range(50):
        key, block = rng.randbytes(16), rng.randbytes(16)
        a = AES(key).trace(block)
        b = AES(key).trace(analysis.flip_bit(block, rng.randrange(128)))
        differing = [sum(x != y for x, y in zip(s, t)) for s, t in zip(a, b)]
        assert differing[0] == 1 and differing[1] == 4
        assert differing[2] >= 15           # після двох раундів зачеплено (майже) весь стан


def test_demo_image_round_trip_through_ppm() -> None:
    w, h, px = demo_image.render()
    assert len(px) == 3 * w * h
    assert demo_image.from_ppm(demo_image.to_ppm(w, h, px)) == (w, h, px)


def test_ecb_keeps_image_structure() -> None:
    from aeslab.aes_fast import FastAES
    w, h, px = demo_image.render()
    c = FastAES(bytes(16))
    ecb = analysis.encrypt_pixels("ECB", c, b"", px)
    ctr = analysis.encrypt_pixels("CTR", c, bytes(16), px)
    assert len(ecb) == len(ctr) == len(px)
    assert analysis.repeated_blocks(ecb)[1] == analysis.repeated_blocks(px)[1]
    total, distinct = analysis.repeated_blocks(ctr)
    assert distinct == total


def test_sbox_design_criteria() -> None:
    props = analysis.sbox_properties()
    assert props["differential_uniformity"] == 4
    assert props["nonlinearity"] == 112 and props["max_linear_bias"] == 16
    assert props["algebraic_degree"] == 7
    assert props["fixed_points"] == props["opposite_fixed_points"] == 0
    assert props["ddt_histogram"] == {0: 255 * 129, 2: 255 * 126, 4: 255}


def test_identity_permutation_is_a_bad_sbox() -> None:
    props = analysis.sbox_properties(list(range(256)))
    assert props["differential_uniformity"] == 256 and props["nonlinearity"] == 0


def test_walsh_transform_matches_direct_count() -> None:
    from aeslab.aes import SBOX
    lat = analysis.sbox_linear_bias()
    for a, b in ((1, 1), (0x53, 0xCA), (0xFF, 0x80)):
        direct = sum((bin(a & x).count("1") & 1) == (bin(b & SBOX[x]).count("1") & 1)
                     for x in range(256)) - 128
        assert lat[a][b] == direct


def test_sac_first_round_touches_one_column_only() -> None:
    mats = analysis.sac_matrices(6, random.Random(3), rounds=(1, 2))
    # після першого раунду інверсія біта 0 зачіпає лише 32 біти одного стовпця
    assert sum(1 for p in mats[1][0] if p > 0) <= 32
    assert sum(1 for p in mats[2][0] if p > 0) > 100


def test_byte_statistics() -> None:
    zeros = analysis.byte_statistics(bytes(4096))
    assert zeros["entropy"] == 0.0 and zeros["distinct_blocks"] == 1
    rnd = analysis.byte_statistics(random.Random(1).randbytes(65536))
    assert rnd["entropy"] > 7.99 and rnd["distinct_blocks"] == rnd["blocks"]
