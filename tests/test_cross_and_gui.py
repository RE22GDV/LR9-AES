"""C#-програма проти Python і перевірка, що інтерфейс запускається."""

from __future__ import annotations

import random
import shutil
import subprocess
from pathlib import Path

import pytest

from aeslab import modes
from aeslab.aes_fast import FastAES

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "csharp" / "AesCtrDemo"
dotnet_required = pytest.mark.skipif(shutil.which("dotnet") is None, reason=".NET SDK не встановлено")


def _run(args: list[str]) -> str:
    proc = subprocess.run(["dotnet", "run", "--project", str(PROJECT), "--"] + args,
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=300, cwd=ROOT)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout.strip()


@dotnet_required
def test_csharp_selftest() -> None:
    out = _run(["selftest"])
    assert "пройдено все" in out and "FAIL" not in out


@dotnet_required
def test_csharp_ctr_matches_python() -> None:
    rng = random.Random(5)
    for n in (0, 1, 16, 31, 100):
        key, ctr, data = rng.randbytes(rng.choice([16, 24, 32])), rng.randbytes(16), rng.randbytes(n)
        expected = modes.ctr_crypt(FastAES(key), ctr, data).hex()
        assert _run(["ctr", key.hex(), ctr.hex(), data.hex() or ""]) == expected


@pytest.fixture(scope="module")
def app():
    # Одне вікно на модуль: повторне створення Tk у Windows зрідка падає з TclError.
    tk = pytest.importorskip("tkinter")
    try:
        from aeslab.gui import AESStudio
        window = AESStudio()
    except tk.TclError as error:
        pytest.skip(f"немає графічного середовища ({error})")
    window.withdraw()
    yield window
    window.destroy()


def test_gui_text_round_trip(app) -> None:
    tab = app.tabs["Текст"]
    for mode in modes.MODES:
        tab.mode.set(mode)
        tab.on_mode()
        tab.plain.delete("1.0", "end")
        tab.plain.insert("1.0", "Привіт, AES! " * 3)
        tab.encrypt()
        tab.plain.delete("1.0", "end")
        tab.decrypt()
        assert tab.plain.get("1.0", "end-1c") == "Привіт, AES! " * 3


def test_gui_other_tabs(app) -> None:
    app.tabs["Зображення"].mode.set("CBC")
    app.tabs["Зображення"].refresh()
    app.tabs["Порівняння режимів"].propagate()
    assert app.tabs["Порівняння режимів"].tree.set("GCM", "error") == "зміну виявлено"
    rounds = app.tabs["Раунди AES"]
    rounds.show()
    assert "69c4e0d86a7b0430d8cdb78070b4c55a" in rounds.text.get("1.0", "end")
