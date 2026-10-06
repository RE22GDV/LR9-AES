"""Узгодженість збережених результатів (docs/results/experiments.json) з кодом."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aeslab import analysis, modes

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "docs" / "results" / "experiments.json"
pytestmark = pytest.mark.skipif(not PATH.exists(), reason="експерименти ще не запускалися")


@pytest.fixture(scope="module")
def results() -> dict:
    return json.loads(PATH.read_text(encoding="utf-8"))


def test_ecb_keeps_block_repetitions(results) -> None:
    blocks = results["image"]["blocks"]
    assert blocks["ECB"]["distinct"] == blocks["original"]["distinct"] < blocks["ECB"]["total"]
    for m in ("CBC", "CTR", "GCM"):
        assert blocks[m]["distinct"] == blocks[m]["total"]


def test_avalanche_curves(results) -> None:
    for curve in results["avalanche"]["curves"].values():
        assert curve[0] == 1
        assert all(60 < x < 68 for x in curve[2:])


def test_error_propagation_table(results) -> None:
    prop = results["errors"]["propagation"]
    assert prop["GCM"] == {"result": "rejected"}
    assert prop["CTR"] == prop["OFB"] == {"bytes": 1, "bits": 1}
    assert prop["ECB"]["bytes"] == 16
    for m in ("CBC", "CFB8", "CFB", "CTS"):
        assert prop[m]["bytes"] == 17


def test_detection_rates(results) -> None:
    det = results["errors"]["detection"]
    assert det["GCM"]["detected"] == det["GCM"]["flips"]
    for m in ("CFB8", "CFB", "OFB", "CTR", "CTS"):
        assert det[m]["detected"] == 0 and det[m]["silent"] == det[m]["flips"]
    for d in results["errors"]["detection_with_hmac"].values():
        assert d["detected"] == d["flips"]


def test_overhead_matches_formula(results) -> None:
    table = results["overhead"]["transmitted"]
    for m in modes.MODES:
        assert table[m] == [analysis.transmitted_length(m, n) for n in results["overhead"]["lengths"]]


def test_parallel_measurements_present(results) -> None:
    par = results["parallel"]
    assert set(par["seconds"]) == {"ctr", "cbc_dec"}
    for kind in par["seconds"].values():
        assert all(v > 0 for v in kind.values())


def test_new_studies(results) -> None:
    assert results["sbox"]["aes"]["nonlinearity"] == 112
    assert results["sbox"]["random_permutation"]["differential_uniformity"] > 4
    dev = results["sac"]["mean_abs_deviation"]
    assert dev["1"] > 0.3 and dev["10"] < 2 * results["sac"]["ideal_deviation"]
    stats = results["statistics"]["stats"]["нулі"]
    assert stats["ECB"]["distinct_blocks"] == 1
    assert all(stats[m]["entropy"] > 7.9 for m in ("CBC", "CTR", "OFB", "GCM"))
    rows = {(r["mode"], r["iv"]): r for r in results["determinism"]["rows"]}
    assert rows[("ECB", "немає IV")]["same_message_same_ciphertext"]
    assert rows[("CBC", "сталий IV")]["common_prefix_bytes"] == 48
    assert not rows[("CBC", "новий випадковий IV")]["same_message_same_ciphertext"]
    assert rows[("CTR", "сталий лічильник")]["common_prefix_bytes"] >= 48
