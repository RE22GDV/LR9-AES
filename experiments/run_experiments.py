"""
Обчислювальні експерименти лабораторної роботи: порівняння режимів AES.

    python experiments/run_experiments.py            # усі експерименти
    python experiments/run_experiments.py --quick    # скорочений прогін

Результати:
    docs/results/experiments.json   — усі виміряні величини
    docs/results/summary.md         — зведена таблиця
    docs/figures/*.png              — рисунки (+ pdf/ — версії без заголовків)

Детерміновані величини (поширення помилки, виявлення змін, лавинний ефект)
обчислюються з фіксованим зерном і відтворюються число в число; час, звісно,
залежить від машини.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import ListedColormap  # noqa: E402
from matplotlib.ticker import PercentFormatter  # noqa: E402

from aeslab import analysis, container, demo_image, modes  # noqa: E402
from aeslab.aes import AES  # noqa: E402
from aeslab.aes_fast import FastAES  # noqa: E402
from aeslab.backends import OpenSSLAES, openssl_available  # noqa: E402

SEED = 20261009

SURFACE, INK, INK_2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e3e2de"
S1, S2, S3, S4 = "#2a78d6", "#eb6834", "#1baf7a", "#8a63d2"
plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID, "axes.labelcolor": INK_2, "axes.titlecolor": INK,
    "axes.titlesize": 12, "axes.titleweight": "semibold", "axes.labelsize": 9.5,
    "axes.grid": True, "axes.axisbelow": True, "grid.color": GRID, "grid.linewidth": 0.8,
    "xtick.color": INK_2, "ytick.color": INK_2, "xtick.labelsize": 8.5,
    "ytick.labelsize": 8.5, "legend.frameon": False, "legend.fontsize": 9,
    "lines.linewidth": 2.0, "font.size": 10,
})

FIG = ROOT / "docs" / "figures"
RES = ROOT / "docs" / "results"
MODE_LABEL = {"ECB": "ECB", "CBC": "CBC", "CFB8": "CFB-8", "CFB": "CFB-128", "OFB": "OFB",
              "CTR": "CTR", "CTS": "CTS", "GCM": "GCM"}


def _n(v: float, d: int = 1) -> str:
    return ("%.*f" % (d, v)).replace(".", ",")


def _finish(ax, note: str | None = None, note_y: float = -0.17) -> None:
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    if note:
        ax.text(0.995, note_y, note, transform=ax.transAxes, ha="right", va="top",
                fontsize=7.5, color=INK_2)


def save(fig, name: str) -> str:
    """Із заголовком — для README; без загального заголовка (pdf/) — для звіту."""
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / name, dpi=200, bbox_inches="tight")
    (FIG / "pdf").mkdir(parents=True, exist_ok=True)
    if fig._suptitle is not None:
        fig.suptitle("")
    fig.savefig(FIG / "pdf" / name, dpi=200, bbox_inches="tight")
    plt.close(fig)
    print("    рисунок -> docs/figures/%s (+ pdf/)" % name)
    return "docs/figures/" + name


def cpu_name() -> str:
    if sys.platform == "win32":
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_Processor).Name"],
                                 capture_output=True, text=True, timeout=30).stdout.strip()
            if out:
                return " ".join(out.split()).replace("(R)", "").replace("(TM)", "")
        except (OSError, subprocess.SubprocessError):
            pass
    return platform.processor() or platform.machine()


# --------------------------------------------------------------------------- #
#  1. ECB і структура даних
# --------------------------------------------------------------------------- #

def exp_image() -> dict:
    print("[1] Зображення: ECB проти інших режимів")
    w, h, px = demo_image.render()
    rng = random.Random(SEED)
    key, iv = rng.randbytes(16), rng.randbytes(16)
    cipher = FastAES(key)
    panels = [("Оригінал", px)]
    stats = {"original": analysis.repeated_blocks(px)}
    for m in ("ECB", "CBC", "CTR", "GCM"):
        enc = analysis.encrypt_pixels(m, cipher, iv[:12] if m == "GCM" else iv, px)
        panels.append((MODE_LABEL[m], enc))
        stats[m] = analysis.repeated_blocks(enc)
    fig, axes = plt.subplots(1, 5, figsize=(12.4, 2.9))
    for ax, (title, data) in zip(axes, panels):
        import numpy as np
        img = np.frombuffer(data, dtype=np.uint8).reshape(h, w, 3)
        ax.imshow(img, interpolation="nearest")
        total, distinct = analysis.repeated_blocks(data)
        ax.set_title(title, fontsize=10.5)
        ax.set_xlabel(f"різних блоків: {distinct} із {total}", fontsize=8)
        ax.set_xticks([])
        ax.set_yticks([])
        ax.grid(False)
    fig.suptitle("Рисунок 1 — Однакові блоки пікселів після шифрування в різних режимах",
                 fontsize=12, fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.9))
    path = save(fig, "fig1_ecb_image.png")
    return {"figure": path, "width": w, "height": h,
            "blocks": {k: {"total": v[0], "distinct": v[1]} for k, v in stats.items()}}


# --------------------------------------------------------------------------- #
#  2. Лавинний ефект за раундами
# --------------------------------------------------------------------------- #

def exp_avalanche(quick: bool) -> dict:
    print("[2] Лавинний ефект за раундами")
    trials = 200 if quick else 2000
    out = {}
    for what, key_len in (("plaintext", 16), ("key", 16), ("plaintext", 32)):
        curve = analysis.avalanche_by_round(trials, random.Random(SEED + key_len), what, key_len)
        out[f"{what}_{8 * key_len}"] = curve
    fig, ax = plt.subplots(figsize=(8.4, 3.9))
    for (name, curve), color, label in zip(out.items(), (S1, S2, S3),
                                           ("AES-128: змінено 1 біт тексту",
                                            "AES-128: змінено 1 біт ключа",
                                            "AES-256: змінено 1 біт тексту")):
        ax.plot(range(len(curve)), curve, "o-", color=color, ms=4, label=label)
    ax.axhline(64, color=INK_2, ls="--", lw=1.2, label="64 біти — половина блоку")
    ax.set_xlabel("номер раунду (0 — після початкового додавання ключа)")
    ax.set_ylabel("відмінних бітів стану з 128")
    ax.set_xticks(range(0, 15))
    ax.legend(loc="lower right", fontsize=8.5)
    _finish(ax, f"середнє за {trials} парами, зерно {SEED}")
    fig.suptitle("Рисунок 2 — Поширення однобітової зміни раундами AES", fontsize=12,
                 fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    path = save(fig, "fig2_avalanche.png")
    return {"figure": path, "trials": trials, "curves": out}


# --------------------------------------------------------------------------- #
#  3. Поширення помилки та виявлення змін
# --------------------------------------------------------------------------- #

def exp_errors() -> dict:
    print("[3] Поширення однобітової помилки шифротексту")
    rng = random.Random(SEED)
    key, iv = rng.randbytes(16), rng.randbytes(16)
    msg = rng.randbytes(64)
    bit = 128 + 5                    # біт у другому блоці шифротексту
    rows, labels, status = [], [], {}
    for m in modes.MODES:
        res = analysis.error_propagation(m, key, iv[:modes.MODE_INFO[m]["iv"]], msg, bit)
        labels.append(MODE_LABEL[m])
        if isinstance(res, list):
            rows.append(res)
            status[m] = {"bytes": sum(1 for v in res if v), "bits": sum(res)}
        else:
            rows.append([-1] * 64)
            status[m] = {"result": res}

    import numpy as np
    data = np.array(rows, dtype=float)
    fig, ax = plt.subplots(figsize=(10.4, 3.9))
    from matplotlib.colors import BoundaryNorm
    cmap = ListedColormap(["#d9d7d0", "#fbf8f3"] + [plt.cm.Oranges(x) for x in np.linspace(0.3, 1, 8)])
    norm = BoundaryNorm([x - 0.5 for x in range(-1, 10)], cmap.N)
    ax.imshow(data, aspect="auto", cmap=cmap, norm=norm, interpolation="nearest")
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xticks(range(0, 65, 8))
    ax.set_xlabel("номер байта відкритого тексту (блоки по 16 байтів)")
    for x in (16, 32, 48):
        ax.axvline(x - 0.5, color="white", lw=1.5)
    for i, m in enumerate(modes.MODES):
        s = status[m]
        text = ("виявлено, текст не видано" if s.get("result") == "rejected"
                else f"{s['bytes']} Б, {s['bits']} біт" if "bytes" in s else s["result"])
        ax.text(64.5, i, text, va="center", fontsize=8.3, color=INK)
    ax.set_xlim(-0.5, 63.5)
    ax.grid(False)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.text(0, -0.9, "колір — кількість хибних бітів у байті (0–8); сірий рядок — розшифрування відхилено",
            fontsize=8, color=INK_2)
    fig.suptitle("Рисунок 3 — Наслідки інверсії одного біта в другому блоці шифротексту",
                 fontsize=12, fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 0.86, 0.95))
    path = save(fig, "fig3_error_propagation.png")

    # Виявлення змін: кожен біт шифротексту 48-байтового повідомлення.
    print("    виявлення змін для кожного біта шифротексту")
    msg2 = rng.randbytes(48)
    detect = {}
    for m in modes.MODES:
        cipher = AES(key)
        ivm = iv[:modes.MODE_INFO[m]["iv"]]
        ct = modes.encrypt(m, cipher, ivm, msg2)
        detected = silent = 0
        for b in range(8 * len(ct)):
            damaged = analysis.flip_bit(ct, b)
            try:
                got = modes.decrypt(m, cipher, ivm, damaged)
            except (modes.AuthenticationError, modes.PaddingError):
                detected += 1
                continue
            silent += got != msg2
        detect[m] = {"flips": 8 * len(ct), "detected": detected, "silent": silent}
    sealed = {}
    for m in ("CBC", "CTR"):
        blob = container.seal(msg2, "pw", m, 16, iterations=1000)
        header_len = container.read_header(blob)[1]
        detected = 0
        positions = range(8 * header_len, 8 * len(blob), 3)
        for b in positions:
            try:
                container.open_sealed(analysis.flip_bit(blob, b), "pw")
            except container.ContainerError:
                detected += 1
        sealed[m] = {"flips": len(positions), "detected": detected}

    fig, ax = plt.subplots(figsize=(8.8, 3.6))
    names = [MODE_LABEL[m] for m in modes.MODES] + ["CBC +\nHMAC", "CTR +\nHMAC"]
    rates = [detect[m]["detected"] / detect[m]["flips"] for m in modes.MODES] + \
            [sealed[m]["detected"] / sealed[m]["flips"] for m in ("CBC", "CTR")]
    colors = [S3 if r > 0.999 else (S2 if r > 0 else INK_2) for r in rates]
    bars = ax.bar(range(len(names)), rates, color=colors, width=0.62)
    for b_, r in zip(bars, rates):
        ax.text(b_.get_x() + b_.get_width() / 2, r + 0.02, _n(100 * r, 1) + " %", ha="center",
                fontsize=8.5)
    ax.set_xticks(range(len(names)), names, fontsize=8.5)
    ax.set_ylabel("частка виявлених змін")
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylim(0, 1.15)
    _finish(ax, "інвертовано кожен біт шифротексту 48-байтового повідомлення окремо; для HMAC — кожен третій біт файла")
    fig.suptitle("Рисунок 4 — Чи помітить одержувач зміну шифротексту", fontsize=12,
                 fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    path2 = save(fig, "fig4_integrity.png")
    return {"figure": path, "figure_integrity": path2, "flipped_bit": bit,
            "propagation": status, "detection": detect, "detection_with_hmac": sealed}


# --------------------------------------------------------------------------- #
#  4. Довжина шифротексту
# --------------------------------------------------------------------------- #

def exp_overhead() -> dict:
    print("[4] Скільки байтів передається")
    ns = list(range(0, 65))
    table = {m: [analysis.transmitted_length(m, n) for n in ns] for m in modes.MODES}
    fig, ax = plt.subplots(figsize=(8.4, 3.9))
    style = {"ECB": (INK_2, "-"), "CBC": (S1, "-"), "CTR": (S3, "-"), "CTS": (S4, "--"),
             "GCM": (S2, "-")}
    for m, (color, ls) in style.items():
        ys = [None if v is None else v - n for v, n in zip(table[m], ns)]
        ax.step(ns, [y if y is not None else float("nan") for y in ys], where="post", color=color,
                ls=ls, label={"CTR": "CTR, OFB, CFB"}.get(m, MODE_LABEL[m]))
    ax.set_xlabel("довжина повідомлення, байтів")
    ax.set_ylabel("додаткових байтів (IV, доповнення, тег)")
    ax.set_ylim(0, 36)
    ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5), fontsize=8.5)
    _finish(ax)
    fig.suptitle("Рисунок 5 — Накладні витрати режимів на довжину", fontsize=12,
                 fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    path = save(fig, "fig5_overhead.png")
    return {"figure": path, "lengths": ns, "transmitted": table}


# --------------------------------------------------------------------------- #
#  5. Швидкість реалізацій і режимів
# --------------------------------------------------------------------------- #

def _speed(fn, nbytes: int, repeats: int = 3) -> float:
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append(nbytes / 1024 / (time.perf_counter() - t0))
    samples.sort()
    return samples[len(samples) // 2]


def exp_speed(quick: bool) -> dict:
    print("[5] Швидкість реалізацій")
    rng = random.Random(SEED)
    key, iv = rng.randbytes(16), rng.randbytes(16)
    impls = {"Еталонна": AES, "Таблична": FastAES}
    if openssl_available():
        impls["OpenSSL (блок)"] = OpenSSLAES
    sizes = {"Еталонна": 4096 if quick else 16384, "Таблична": 65536 if quick else 262144,
             "OpenSSL (блок)": 65536 if quick else 262144}
    by_mode = {}
    for name, cls in impls.items():
        data = rng.randbytes(sizes[name])
        cipher = cls(key)
        by_mode[name] = {}
        for m in modes.MODES:
            ivm = iv[:modes.MODE_INFO[m]["iv"]]
            by_mode[name][m] = _speed(lambda: modes.encrypt(m, cipher, ivm, data), len(data))
        print(f"    {name}: " + ", ".join(f"{m} {v:,.0f}" for m, v in by_mode[name].items()))
    key_sizes = {}
    for kl in (16, 24, 32):
        data = rng.randbytes(65536 if quick else 262144)
        c = FastAES(rng.randbytes(kl))
        key_sizes[8 * kl] = _speed(lambda: modes.ecb_encrypt(c, data, pad=False), len(data))
    native = None
    if openssl_available():
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        from cryptography.hazmat.primitives.ciphers import modes as cm
        big = rng.randbytes(16 << 20)

        def run_native():
            e = Cipher(algorithms.AES(key), cm.CTR(iv)).encryptor()
            e.update(big)
            e.finalize()
        native = _speed(run_native, len(big))
    csharp = None
    if shutil.which("dotnet"):
        proc = subprocess.run(["dotnet", "run", "-c", "Release", "--project",
                               str(ROOT / "csharp" / "AesCtrDemo"), "--", "bench"],
                              capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=600)
        if proc.returncode == 0:
            csharp = json.loads(proc.stdout.strip().splitlines()[-1])

    fig, axes = plt.subplots(1, 2, figsize=(11.2, 4.2), gridspec_kw={"width_ratios": [1.65, 1]})
    ax = axes[0]
    width = 0.27
    for i, (name, color) in enumerate(zip(impls, (INK_2, S1, S3))):
        vals = [by_mode[name][m] for m in modes.MODES]
        ax.bar([x + (i - 1) * width for x in range(len(modes.MODES))], vals, width=width,
               color=color, label=name)
    ax.set_yscale("log")
    ax.set_xticks(range(len(modes.MODES)), [MODE_LABEL[m] for m in modes.MODES], fontsize=8.5)
    ax.set_ylabel("КБ/с (логарифмічна шкала)")
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(
        lambda v, _: f"{v:,.0f}".replace(",", " ")))
    ax.set_title("а) режими в Python над трьома реалізаціями блоку")
    ax.set_ylim(top=max(max(v.values()) for v in by_mode.values()) * 12)
    ax.legend(fontsize=8, loc="upper center", ncol=3)
    _finish(ax)
    ax = axes[1]
    labels = ["Python,\nеталонна", "Python,\nтаблична", "Python +\nблок OpenSSL"]
    values = [by_mode[n]["CTR"] for n in impls]
    colors = [INK_2, S1, S3][:len(values)]
    if csharp:
        labels.append("C# AesCtr\n(.NET AES)")
        values.append(csharp["kib_per_s_median"])
        colors.append(S4)
    if native:
        labels.append("OpenSSL CTR\nцілком")
        values.append(native)
        colors.append(S2)
    mb = [v / 1024 for v in values]
    bars = ax.bar(range(len(mb)), mb, color=colors, width=0.62)
    for b_, v in zip(bars, mb):
        text = f"{v:,.0f}".replace(",", " ") if v >= 10 else _n(v, 2)
        ax.text(b_.get_x() + b_.get_width() / 2, v * 1.25, text, ha="center", fontsize=8)
    ax.set_yscale("log")
    ax.set_ylim(min(mb) / 2, max(mb) * 8)
    ax.set_ylabel("МБ/с (логарифмічна шкала)")
    ax.set_xticks(range(len(mb)), labels, fontsize=7.8)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(
        lambda v, _: (f"{v:,.0f}".replace(",", " ") if v >= 1 else _n(v, 1))))
    ax.set_title("б) режим CTR у різних реалізаціях")
    _finish(ax, f"{cpu_name()}; Python {platform.python_version()}", note_y=-0.22)
    fig.suptitle("Рисунок 6 — Швидкість шифрування (медіана трьох повторів)", fontsize=12,
                 fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    path = save(fig, "fig6_speed.png")
    return {"figure": path, "kib_per_s": by_mode, "fast_aes_by_key_bits": key_sizes,
            "openssl_native_ctr": native, "csharp_ctr": csharp,
            "machine": {"cpu": cpu_name(), "python": platform.python_version()}}


# --------------------------------------------------------------------------- #
#  6. Паралельність: CTR і розшифрування CBC проти шифрування CBC
# --------------------------------------------------------------------------- #

def _ctr_chunk(args):
    key, counter, data, first = args
    c = FastAES(key)
    start = (int.from_bytes(counter, "big") + first) % (1 << 128)
    return modes.ctr_crypt(c, start.to_bytes(16, "big"), data)


def _cbc_dec_chunk(args):
    key, prev, data = args
    return modes.cbc_decrypt(FastAES(key), prev, data, pad=False)


def exp_parallel(quick: bool) -> dict:
    print("[6] Паралельна обробка")
    rng = random.Random(SEED)
    key, iv = rng.randbytes(16), rng.randbytes(16)
    data = rng.randbytes((256 if quick else 2048) * 1024)
    cbc = modes.cbc_encrypt(FastAES(key), iv, data, pad=False)
    workers_list = [1, 2, 4, 8] if quick else [1, 2, 4, 6, 8, 12, 16]
    workers_list = [w for w in workers_list if w <= (os.cpu_count() or 1)]
    times = {"ctr": {}, "cbc_dec": {}}
    t0 = time.perf_counter()
    modes.cbc_encrypt(FastAES(key), iv, data, pad=False)
    cbc_enc_time = time.perf_counter() - t0
    for w in workers_list:
        n_blocks = len(data) // 16
        bounds = [n_blocks * i // w for i in range(w + 1)]
        ctr_jobs = [(key, iv, data[16 * a:16 * b], a) for a, b in zip(bounds, bounds[1:])]
        dec_jobs = [(key, iv if a == 0 else cbc[16 * a - 16:16 * a], cbc[16 * a:16 * b])
                    for a, b in zip(bounds, bounds[1:])]
        with mp.Pool(w) as pool:
            pool.map(_ctr_chunk, ctr_jobs)          # прогрів: процеси встигають «розігнатися»
            samples = {"ctr": [], "cbc_dec": []}
            for rep in range(5):                     # чергування порядку, мінімум із п’яти
                order = ("ctr", "cbc_dec") if rep % 2 == 0 else ("cbc_dec", "ctr")
                for kind in order:
                    t0 = time.perf_counter()
                    if kind == "ctr":
                        ctr_out = b"".join(pool.map(_ctr_chunk, ctr_jobs))
                    else:
                        dec_out = b"".join(pool.map(_cbc_dec_chunk, dec_jobs))
                    samples[kind].append(time.perf_counter() - t0)
            for kind in samples:
                times[kind][w] = min(samples[kind])
        assert dec_out == data
        print(f"    {w:2d} процесів: CTR {times['ctr'][w]:.2f} с, розшифр. CBC {times['cbc_dec'][w]:.2f} с")
    assert b"".join(_ctr_chunk(j) for j in [(key, iv, data, 0)]) == ctr_out
    fig, ax = plt.subplots(figsize=(8.4, 3.9))
    for kind, color, label in (("ctr", S3, "CTR: шифрування"), ("cbc_dec", S1, "CBC: розшифрування")):
        base = times[kind][1]
        ax.plot(workers_list, [base / times[kind][w] for w in workers_list], "o-", color=color,
                ms=5, label=label)
    ax.plot(workers_list, [1] * len(workers_list), "s--", color=S2, ms=5,
            label="CBC: шифрування (лише послідовно)")
    ax.plot(workers_list, workers_list, ":", color=INK_2, lw=1.2, label="ідеальне прискорення")
    ax.set_xlabel("кількість процесів")
    ax.set_ylabel("прискорення відносно 1 процесу")
    ax.set_xticks(workers_list)
    ax.legend(loc="upper left", fontsize=8.5)
    _finish(ax, f"{len(data) // 1024} КіБ, таблична реалізація; {cpu_name()}")
    fig.suptitle("Рисунок 7 — Які режими можна розпаралелити", fontsize=12, fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    path = save(fig, "fig7_parallel.png")
    return {"figure": path, "bytes": len(data), "workers": workers_list,
            "seconds": {k: {str(w): v for w, v in d.items()} for k, d in times.items()},
            "cbc_encrypt_seconds": cbc_enc_time}



# --------------------------------------------------------------------------- #
#  7. Строгий лавинний критерій
# --------------------------------------------------------------------------- #

def exp_sac(quick: bool) -> dict:
    print("[7] Строгий лавинний критерій (матриці 128 × 128)")
    import numpy as np
    trials = 40 if quick else 400
    rounds = (1, 2, 3, 10)
    mats = analysis.sac_matrices(trials, random.Random(SEED + 7), rounds)
    dev = {r: float(np.mean(np.abs(np.array(m) - 0.5))) for r, m in mats.items()}
    zero_share = {r: float(np.mean(np.array(m) == 0)) for r, m in mats.items()}
    # Очікуване |p − ½| для ідеального шифру за обмеженої вибірки (біноміальний шум)
    ideal = float(np.mean(np.abs(np.random.default_rng(SEED).binomial(trials, 0.5, 200_000) / trials - 0.5)))
    fig, axes = plt.subplots(1, 4, figsize=(12.4, 3.6))
    for ax, r in zip(axes, rounds):
        im = ax.imshow(mats[r], cmap="RdBu_r", vmin=0, vmax=1, interpolation="nearest")
        ax.set_title(f"раунд {r}", fontsize=10.5)
        ax.set_xlabel(f"|p − ½| = {_n(dev[r], 3)}", fontsize=8.5)
        ax.set_xticks([0, 64, 127])
        ax.set_yticks([0, 64, 127])
        ax.tick_params(labelsize=7)
        ax.grid(False)
    axes[0].set_ylabel("інвертований вхідний біт", fontsize=8.5)
    cb = fig.colorbar(im, ax=axes, fraction=0.02, pad=0.02)
    cb.set_label("P(вихідний біт змінився)", fontsize=8.5)
    fig.suptitle("Рисунок 8 — Строгий лавинний критерій: ймовірність зміни кожного біта виходу",
                 fontsize=12, fontweight="semibold")
    path = save(fig, "fig8_sac.png")
    return {"figure": path, "trials": trials, "mean_abs_deviation": {str(r): v for r, v in dev.items()},
            "zero_share": {str(r): v for r, v in zero_share.items()}, "ideal_deviation": ideal}


# --------------------------------------------------------------------------- #
#  8. Властивості S-блоку
# --------------------------------------------------------------------------- #

def exp_sbox() -> dict:
    print("[8] Критерії стійкості S-блоку")
    import numpy as np
    props = analysis.sbox_properties()
    ddt = np.array(analysis.sbox_ddt())
    lat = np.array(analysis.sbox_linear_bias())
    # Для порівняння — випадкова перестановка байтів
    rng = random.Random(SEED + 8)
    perm = list(range(256))
    rng.shuffle(perm)
    rand_props = analysis.sbox_properties(perm)
    fig, axes = plt.subplots(1, 3, figsize=(12.4, 3.9), gridspec_kw={"width_ratios": [1, 1, 1.15]})
    from matplotlib.colors import ListedColormap
    axes[0].imshow(ddt[1:], cmap=ListedColormap(["#fbf8f3", "#f4a582", "#b2182b"]), vmin=0, vmax=4,
                   aspect="auto", interpolation="nearest")
    axes[0].set_title("а) таблиця різниць (a ≠ 0)", fontsize=10.5)
    axes[0].set_xlabel("вихідна різниця b", fontsize=8.5)
    axes[0].set_ylabel("вхідна різниця a", fontsize=8.5)
    axes[0].grid(False)
    axes[1].imshow(np.abs(lat[:, 1:]), cmap="Blues", vmin=0, vmax=16, aspect="auto",
                   interpolation="nearest")
    axes[1].set_title("б) |лінійне зміщення| (b ≠ 0)", fontsize=10.5)
    axes[1].set_xlabel("вихідна маска b", fontsize=8.5)
    axes[1].set_ylabel("вхідна маска a", fontsize=8.5)
    axes[1].grid(False)
    ax = axes[2]
    names = ["диференційна\nрівномірність", "найбільше\n|зміщення|", "алгебраїчний\nстепінь"]
    aes_vals = [props["differential_uniformity"], props["max_linear_bias"], props["algebraic_degree"]]
    rnd_vals = [rand_props["differential_uniformity"], rand_props["max_linear_bias"], rand_props["algebraic_degree"]]
    x = range(3)
    ax.bar([i - 0.18 for i in x], aes_vals, width=0.36, color=S1, label="S-блок AES")
    ax.bar([i + 0.18 for i in x], rnd_vals, width=0.36, color=INK_2, label="випадкова перестановка")
    for i, (a, b) in enumerate(zip(aes_vals, rnd_vals)):
        ax.text(i - 0.18, a + 0.6, str(a), ha="center", fontsize=8.5)
        ax.text(i + 0.18, b + 0.6, str(b), ha="center", fontsize=8.5)
    ax.set_xticks(list(x), names, fontsize=8)
    ax.set_title("в) менше — краще (крім степеня)", fontsize=10.5)
    ax.legend(fontsize=8, loc="upper right")
    _finish(ax)
    fig.suptitle("Рисунок 9 — Чому S-блок AES побудовано саме так", fontsize=12, fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    path = save(fig, "fig9_sbox.png")
    return {"figure": path, "aes": props, "random_permutation": rand_props}


# --------------------------------------------------------------------------- #
#  9. Статистика шифротексту для одноманітних даних
# --------------------------------------------------------------------------- #

def exp_statistics(quick: bool) -> dict:
    print("[9] Статистика байтів шифротексту")
    rng = random.Random(SEED + 9)
    size = 8192 if quick else 32768
    line = "Звіт за жовтень: ДОХІД 100 000 UAH.".encode("utf-8")
    inputs = {"нулі": bytes(size), "повторюваний текст": (line * (size // len(line) + 1))[:size],
              "випадкові дані": rng.randbytes(size)}
    key, iv = rng.randbytes(16), rng.randbytes(16)
    cipher = FastAES(key)
    out = {}
    for name, data in inputs.items():
        out[name] = {"plaintext": analysis.byte_statistics(data)}
        for m in modes.MODES:
            ct = modes.encrypt(m, cipher, iv[:modes.MODE_INFO[m]["iv"]], data)
            out[name][m] = analysis.byte_statistics(ct[:size])
    fig, axes = plt.subplots(1, 2, figsize=(11.2, 3.9))
    labels = ["текст"] + [MODE_LABEL[m] for m in modes.MODES]
    keys = ["plaintext"] + list(modes.MODES)
    width = 0.27
    for i, (name, color) in enumerate(zip(inputs, (INK_2, S2, S1))):
        axes[0].bar([x + (i - 1) * width for x in range(len(keys))],
                    [out[name][k]["entropy"] for k in keys], width=width, color=color, label=name)
        axes[1].bar([x + (i - 1) * width for x in range(len(keys))],
                    [out[name][k]["distinct_blocks"] / out[name][k]["blocks"] for k in keys],
                    width=width, color=color, label=name)
    axes[0].axhline(8, color=INK_2, ls="--", lw=1)
    axes[0].set_ylabel("ентропія, біт на байт")
    axes[0].set_ylim(0, 8.8)
    axes[0].set_title("а) ентропія розподілу байтів")
    axes[1].set_ylabel("частка різних блоків")
    axes[1].yaxis.set_major_formatter(PercentFormatter(1.0))
    axes[1].set_ylim(0, 1.12)
    axes[1].set_title("б) різні 16-байтові блоки")
    for ax in axes:
        ax.set_xticks(range(len(keys)), labels, fontsize=8)
        _finish(ax)
    handles, labels_ = axes[1].get_legend_handles_labels()
    fig.legend(handles, labels_, loc="lower center", ncol=3, fontsize=8.5, bbox_to_anchor=(0.5, -0.02))
    fig.suptitle(f"Рисунок 10 — Шифротекст одноманітних даних ({size // 1024} КіБ)", fontsize=12,
                 fontweight="semibold")
    fig.tight_layout(rect=(0, 0.06, 1, 0.92))
    path = save(fig, "fig10_statistics.png")
    return {"figure": path, "bytes": size, "stats": out}


# --------------------------------------------------------------------------- #
#  10. Вартість: PBKDF2 і час на коротке повідомлення
# --------------------------------------------------------------------------- #

def exp_cost(quick: bool) -> dict:
    print("[10] Вартість PBKDF2 і час на повідомлення")
    import hashlib
    iterations = [1_000, 10_000, 50_000, 100_000, 200_000, 600_000]
    pbkdf2 = {}
    for n in iterations:
        samples = []
        for _ in range(3):
            t0 = time.perf_counter()
            hashlib.pbkdf2_hmac("sha256", b"password", b"salt" * 4, n, 64)
            samples.append(time.perf_counter() - t0)
        pbkdf2[n] = min(samples)
    rng = random.Random(SEED + 10)
    key = rng.randbytes(16)
    cipher = FastAES(key)
    sizes = [16, 64, 256, 1024, 4096, 16384]
    per_msg = {m: {} for m in ("CTR", "CBC", "GCM", "GCM_new_key")}
    for m in per_msg:
        mode = "GCM" if m.startswith("GCM") else m
        for n in sizes:
            data = rng.randbytes(n)
            iv = rng.randbytes(modes.MODE_INFO[mode]["iv"])
            reps = max(3, (2000 if quick else 20000) // n)
            t0 = time.perf_counter()
            for _ in range(reps):
                # «новий ключ»: свіжий об'єкт шифру, таблиці GHASH будуються щоразу
                c = FastAES(key) if m == "GCM_new_key" else cipher
                modes.encrypt(mode, c, iv, data)
            per_msg[m][n] = (time.perf_counter() - t0) / reps
    fig, axes = plt.subplots(1, 2, figsize=(11.2, 3.9))
    ax = axes[0]
    ax.loglog(iterations, [pbkdf2[n] * 1000 for n in iterations], "o-", color=S1)
    note = "\n".join(f"{n // 1000} тис. ітерацій: {_n(pbkdf2[n] * 1000, 0)} мс, "
                     f"≈ {_n(1 / pbkdf2[n], 1)} спроби/с на ядро" for n in (200_000, 600_000))
    ax.text(0.97, 0.06, note, transform=ax.transAxes, ha="right", va="bottom", fontsize=8.3,
            color=INK, bbox=dict(boxstyle="round,pad=0.4", fc="white", ec=GRID))
    for n in (200_000, 600_000):
        ax.plot([n], [pbkdf2[n] * 1000], "o", color=S2, ms=7, zorder=3)
    ax.set_xlabel("ітерацій PBKDF2-HMAC-SHA256")
    ax.set_ylabel("мс на одне виведення ключа")
    ax.set_title("а) ціна однієї перевірки пароля")
    _finish(ax)
    ax = axes[1]
    for m, color, ls, label in (("CTR", S3, "-", "CTR"), ("CBC", S1, "-", "CBC"),
                                ("GCM", S2, "-", "GCM, той самий ключ"),
                                ("GCM_new_key", S4, "--", "GCM, новий ключ щоразу")):
        ax.loglog(sizes, [per_msg[m][n] * 1e6 for n in sizes], ("s" if "new" in m else "o") + ls,
                  color=color, label=label, ms=4)
    ax.set_xlabel("довжина повідомлення, байтів")
    ax.set_ylabel("мкс на повідомлення")
    ax.set_title("б) час на одне повідомлення (таблична реалізація)")
    ax.legend(fontsize=8.5)
    _finish(ax, f"{cpu_name()}")
    fig.suptitle("Рисунок 11 — Вартість ключа з пароля та накладні витрати режимів", fontsize=12,
                 fontweight="semibold")
    fig.tight_layout(rect=(0, 0, 1, 0.92))
    path = save(fig, "fig11_cost.png")
    return {"figure": path, "pbkdf2_seconds": {str(k): v for k, v in pbkdf2.items()},
            "per_message_seconds": {m: {str(k): v for k, v in d.items()} for m, d in per_msg.items()}}


# --------------------------------------------------------------------------- #
#  11. Детермінованість: однакові повідомлення й спільні префікси
# --------------------------------------------------------------------------- #

def exp_determinism() -> dict:
    print("[11] Однакові повідомлення: що бачить спостерігач")
    rng = random.Random(SEED + 11)
    key = rng.randbytes(16)
    cipher = FastAES(key)
    a = b"Transfer 100 UAH to account 0001, date 2026-10-06."
    b = b"Transfer 100 UAH to account 0001, date 2026-10-07."
    fixed16 = rng.randbytes(16)
    cases = [
        ("ECB", lambda: b"", "немає IV"),
        ("CBC", lambda: fixed16, "сталий IV"),
        ("CBC", lambda: rng.randbytes(16), "новий випадковий IV"),
        ("CTR", lambda: fixed16, "сталий лічильник"),
        ("CTR", lambda: rng.randbytes(16), "новий лічильник"),
        ("GCM", lambda: rng.randbytes(12), "новий nonce"),
    ]
    rows = []
    for mode, iv_fn, label in cases:
        iv1, iv2 = iv_fn(), iv_fn()
        c1, c2 = modes.encrypt(mode, cipher, iv1, a), modes.encrypt(mode, cipher, iv1, a)
        same_twice = c1 == c2 if label.startswith(("немає", "сталий")) else \
            modes.encrypt(mode, cipher, iv1, a) == modes.encrypt(mode, cipher, iv2, a)
        ca, cb = modes.encrypt(mode, cipher, iv1, a), modes.encrypt(mode, cipher, iv2, b)
        common = 0
        while common < min(len(ca), len(cb)) and ca[common] == cb[common]:
            common += 1
        rows.append({"mode": mode, "iv": label, "same_message_same_ciphertext": same_twice,
                     "common_prefix_bytes": common, "plaintext_common_prefix": 48})
    return {"messages": [a.decode(), b.decode()], "rows": rows}

# --------------------------------------------------------------------------- #

def write_summary(results: dict) -> None:
    RES.mkdir(parents=True, exist_ok=True)
    (RES / "experiments.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n",
                                          encoding="utf-8")
    L = ["# Зведені результати експериментів", "",
         "Згенеровано автоматично: `python experiments/run_experiments.py`", "",
         "## Інверсія одного біта шифротексту (64-байтове повідомлення)", "",
         "| Режим | Наслідок |", "|---|---|"]
    for m, s in results["errors"]["propagation"].items():
        text = "зміну виявлено" if s.get("result") == "rejected" else f"{s['bytes']} Б, {s['bits']} біт"
        L.append(f"| {MODE_LABEL[m]} | {text} |")
    L += ["", "## Виявлення змін (кожен біт шифротексту 48-байтового повідомлення)", "",
          "| Режим | Інверсій | Виявлено | Тихо зіпсовано |", "|---|---:|---:|---:|"]
    for m, d in results["errors"]["detection"].items():
        L.append(f"| {MODE_LABEL[m]} | {d['flips']} | {d['detected']} | {d['silent']} |")
    L += ["", "## Швидкість, КБ/с", "", "| Режим | " + " | ".join(results["speed"]["kib_per_s"]) + " |",
          "|---|" + "---:|" * len(results["speed"]["kib_per_s"])]
    for m in modes.MODES:
        L.append(f"| {MODE_LABEL[m]} | " + " | ".join(f"{v[m]:.0f}" for v in results["speed"]["kib_per_s"].values()) + " |")
    L += ["", "## Однакові повідомлення", "", "| Режим | IV | Однаковий шифротекст | Спільний префікс, Б |",
          "|---|---|---|---:|"]
    for r in results["determinism"]["rows"]:
        L.append(f"| {r['mode']} | {r['iv']} | {'так' if r['same_message_same_ciphertext'] else 'ні'} | "
                 f"{r['common_prefix_bytes']} |")
    s = results["sbox"]["aes"]
    L += ["", "## S-блок AES", "", f"- диференційна рівномірність: {s['differential_uniformity']}",
          f"- нелінійність: {s['nonlinearity']}", f"- алгебраїчний степінь: {s['algebraic_degree']}"]
    (RES / "summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n    зведення -> docs/results/summary.md")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    t0 = time.perf_counter()
    results = {
        "seed": SEED,
        "quick": args.quick,
        "image": exp_image(),
        "avalanche": exp_avalanche(args.quick),
        "errors": exp_errors(),
        "overhead": exp_overhead(),
        "speed": exp_speed(args.quick),
        "parallel": exp_parallel(args.quick),
        "sac": exp_sac(args.quick),
        "sbox": exp_sbox(),
        "statistics": exp_statistics(args.quick),
        "cost": exp_cost(args.quick),
        "determinism": exp_determinism(),
        "properties": {m: dict(zip(analysis.PROPERTY_NAMES, v)) for m, v in analysis.PROPERTIES.items()},
        "property_notes": list(analysis.PROPERTY_NOTES),
    }
    results["elapsed_s"] = round(time.perf_counter() - t0, 1)
    write_summary(results)
    print(f"готово за {results['elapsed_s']} с")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
