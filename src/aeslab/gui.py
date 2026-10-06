"""AES Studio — програма для шифрування з графічним інтерфейсом (Tkinter).

    python run.py gui
    python run.py gui --screenshot docs/figures     # знімки вкладок для звіту

Вкладки:
  «Текст»       — шифрування й розшифрування тексту в будь-якому режимі;
  «Файли»       — файли з паролем (PBKDF2, контроль цілісності);
  «Зображення»  — наочна різниця між ECB і рештою режимів;
  «Порівняння»  — властивості режимів, швидкість, поширення помилки;
  «Раунди AES»  — стан шифру після кожного раунду й лавинний ефект.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import secrets
import string
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import analysis, container, demo_image, modes
from .aes import AES, INV_SBOX, SBOX
from .backends import IMPLEMENTATIONS

MODE_TITLES = {
    "ECB": "ECB — кожен блок окремо",
    "CBC": "CBC — зчеплення блоків",
    "CFB8": "CFB-8 — зворотний зв'язок за шифротекстом, по байту",
    "CFB": "CFB-128 — зворотний зв'язок за шифротекстом, по блоку",
    "OFB": "OFB — зворотний зв'язок за виходом",
    "CTR": "CTR — лічильник",
    "CTS": "CTS — CBC з «крадіжкою» шифротексту",
    "GCM": "GCM — лічильник + автентифікація",
}
MODE_NOTES = {
    "ECB": "Однакові блоки відкритого тексту дають однакові блоки шифротексту — структура даних видна.",
    "CBC": "Потрібен непередбачуваний IV. Без MAC зміни шифротексту не виявляються.",
    "CFB8": "Потоковий режим без доповнення; IV непередбачуваний, помилка зачіпає ще 16 байтів.",
    "CFB": "Потоковий режим без доповнення; потрібен непередбачуваний IV.",
    "OFB": "Ключовий потік не залежить від даних; повторний IV розкриває XOR текстів.",
    "CTR": "Блоки незалежні, але для ключа жоден блок лічильника не повторюється, і між повідомленнями теж.",
    "CTS": "Довжина шифротексту дорівнює довжині тексту (не менше 16 байтів).",
    "GCM": "Автентифіковане шифрування: будь-яка зміна шифротексту виявляється.",
}

if sys.platform == "win32":
    UI_FAMILY, MONO_FAMILY = "Segoe UI", "Consolas"
elif sys.platform == "darwin":
    UI_FAMILY, MONO_FAMILY = "Helvetica Neue", "Menlo"
else:
    UI_FAMILY, MONO_FAMILY = "DejaVu Sans", "DejaVu Sans Mono"

ACCENT = "#2a78d6"
WARN = "#c4561d"
OK = "#1a8f63"
MONO = (MONO_FAMILY, 10)
BLOCK_COLORS = ("#fde1d3", "#d6e8fb", "#d3f2e5", "#e8dff8", "#fbefc9", "#f9d6e3")


def _hex(data: bytes) -> str:
    return data.hex()


def _parse_hex(text: str) -> bytes:
    cleaned = "".join(text.split())
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("очікується шістнадцятковий рядок") from exc


class TextTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=12)
        self.app = app
        self.used_nonces: set[tuple[bytes, bytes, str]] = set()

        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="Режим:").grid(row=0, column=0, sticky="w")
        self.mode = tk.StringVar(value="GCM")
        cb = ttk.Combobox(top, textvariable=self.mode, values=list(modes.MODES), width=8,
                          state="readonly")
        cb.grid(row=0, column=1, sticky="w", padx=(4, 16))
        cb.bind("<<ComboboxSelected>>", lambda e: self.on_mode())
        ttk.Label(top, text="Ключ:").grid(row=0, column=2, sticky="w")
        self.key_bits = tk.IntVar(value=256)
        for i, bits in enumerate((128, 192, 256)):
            ttk.Radiobutton(top, text=f"{bits} біт", value=bits, variable=self.key_bits,
                            command=self.new_key).grid(row=0, column=3 + i, padx=2)
        ttk.Label(top, text="Реалізація:").grid(row=0, column=6, sticky="e", padx=(16, 4))
        self.impl = tk.StringVar(value="Таблична (T-таблиці)")
        ttk.Combobox(top, textvariable=self.impl, values=list(IMPLEMENTATIONS), width=24,
                     state="readonly").grid(row=0, column=7, sticky="w")

        self.mode_title = ttk.Label(self, font=(UI_FAMILY, 11, "bold"))
        self.mode_title.pack(anchor="w", pady=(10, 0))
        self.mode_note = ttk.Label(self, foreground="#52514e")
        self.mode_note.pack(anchor="w")

        keys = ttk.Frame(self)
        keys.pack(fill="x", pady=(8, 4))
        keys.columnconfigure(1, weight=1)
        ttk.Label(keys, text="Ключ (hex):").grid(row=0, column=0, sticky="w")
        self.key = tk.StringVar()
        ttk.Entry(keys, textvariable=self.key, font=MONO).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Button(keys, text="Згенерувати", command=self.new_key).grid(row=0, column=2)
        ttk.Label(keys, text="IV / nonce (hex):").grid(row=1, column=0, sticky="w", pady=4)
        self.iv = tk.StringVar()
        self.iv_entry = ttk.Entry(keys, textvariable=self.iv, font=MONO)
        self.iv_entry.grid(row=1, column=1, sticky="ew", padx=4)
        self.iv_button = ttk.Button(keys, text="Згенерувати", command=self.new_iv)
        self.iv_button.grid(row=1, column=2)
        ttk.Label(keys, text="Дод. дані AAD (GCM):").grid(row=2, column=0, sticky="w")
        self.aad = tk.StringVar()
        self.aad_entry = ttk.Entry(keys, textvariable=self.aad)
        self.aad_entry.grid(row=2, column=1, sticky="ew", padx=4)
        ttk.Button(keys, text="Ключ із пароля…", command=self.key_from_password).grid(row=2, column=2)

        tools = ttk.Frame(self)
        tools.pack(fill="x", pady=(2, 0))
        ttk.Button(tools, text="Відкрити текст…", command=self.open_text).pack(side="left")
        ttk.Button(tools, text="Зберегти шифротекст…", command=self.save_cipher).pack(side="left", padx=6)
        ttk.Button(tools, text="Копіювати шифротекст", command=self.copy_cipher).pack(side="left")
        ttk.Label(tools, text="у hex-вигляді однакові блоки шифротексту підсвічено однаковим кольором",
                  foreground="#8a8984").pack(side="right")

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, pady=(8, 0))
        body.columnconfigure(0, weight=1)
        body.columnconfigure(2, weight=1)
        body.rowconfigure(1, weight=1)
        ttk.Label(body, text="Відкритий текст (UTF-8)").grid(row=0, column=0, sticky="w")
        out_head = ttk.Frame(body)
        out_head.grid(row=0, column=2, sticky="ew")
        ttk.Label(out_head, text="Шифротекст").pack(side="left")
        self.fmt = tk.StringVar(value="hex")
        ttk.Radiobutton(out_head, text="hex", value="hex", variable=self.fmt,
                        command=self.reformat).pack(side="right")
        ttk.Radiobutton(out_head, text="Base64", value="b64", variable=self.fmt,
                        command=self.reformat).pack(side="right", padx=6)
        self.plain = tk.Text(body, height=10, wrap="word", font=(UI_FAMILY, 10), undo=True)
        self.plain.grid(row=1, column=0, sticky="nsew")
        buttons = ttk.Frame(body)
        buttons.grid(row=1, column=1, padx=10)
        ttk.Button(buttons, text="Зашифрувати →", style="Accent.TButton",
                   command=self.encrypt).pack(fill="x", pady=4)
        ttk.Button(buttons, text="← Розшифрувати", command=self.decrypt).pack(fill="x", pady=4)
        self.cipher_text = tk.Text(body, height=10, wrap="char", font=MONO)
        self.cipher_text.grid(row=1, column=2, sticky="nsew")
        self.info = ttk.Label(self, foreground="#52514e", wraplength=1000, justify="left")
        self.info.pack(anchor="w", pady=(8, 0))
        self.last_cipher = b""

        self.plain.insert("1.0", "Лабораторна робота №9: AES. Однакові блоки — однаковий шифротекст? "
                                 "Перевірте в режимі ECB: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        self.new_key()
        self.on_mode()

    # --- допоміжне
    def cipher(self):
        key = _parse_hex(self.key.get())
        if len(key) not in (16, 24, 32):
            raise ValueError("ключ має містити 16, 24 або 32 байти (32, 48 або 64 hex-символи)")
        return IMPLEMENTATIONS[self.impl.get()](key)

    def new_key(self):
        self.key.set(os.urandom(self.key_bits.get() // 8).hex())

    def new_iv(self):
        n = modes.MODE_INFO[self.mode.get()]["iv"]
        self.iv.set(os.urandom(n).hex() if n else "")

    def on_mode(self):
        m = self.mode.get()
        self.mode_title.config(text=MODE_TITLES[m])
        self.mode_note.config(text=MODE_NOTES[m],
                              foreground=WARN if m == "ECB" else ("#52514e" if m != "GCM" else OK))
        need_iv = modes.MODE_INFO[m]["iv"] > 0
        self.iv_entry.config(state="normal" if need_iv else "disabled")
        self.iv_button.config(state="normal" if need_iv else "disabled")
        self.aad_entry.config(state="normal" if m == "GCM" else "disabled")
        self.new_iv()

    def show_cipher(self, data: bytes):
        self.last_cipher = data
        self.reformat()

    def reformat(self):
        box = self.cipher_text
        box.delete("1.0", "end")
        if self.fmt.get() != "hex":
            box.insert("1.0", base64.b64encode(self.last_cipher).decode())
            return
        data = self.last_cipher
        blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
        counts = {}
        for b in blocks:
            if len(b) == 16:
                counts[b] = counts.get(b, 0) + 1
        colors = {}
        for i, b in enumerate(blocks):
            tag = ""
            if counts.get(b, 0) > 1:                 # повторюваний блок — свій колір
                if b not in colors:
                    colors[b] = f"rep{len(colors) % len(BLOCK_COLORS)}"
                tag = colors[b]
            box.insert("end", b.hex(" "), tag)
            box.insert("end", "\n" if i < len(blocks) - 1 else "")
        for k, color in enumerate(BLOCK_COLORS):
            box.tag_configure(f"rep{k}", background=color)

    def key_from_password(self):
        pw = simpledialog.askstring("Ключ із пароля", "Пароль:", show="•", parent=self)
        if not pw:
            return
        salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, container.DEFAULT_ITERATIONS,
                                  self.key_bits.get() // 8)
        self.key.set(key.hex())
        self.info.config(text=f"Ключ виведено PBKDF2-HMAC-SHA256 ({container.DEFAULT_ITERATIONS:,} ітерацій), "
                              f"сіль {salt.hex()} — ".replace(",", " ") +
                              "її треба зберегти, щоб знову отримати той самий ключ.",
                         foreground="#52514e")

    def open_text(self):
        path = filedialog.askopenfilename(filetypes=[("Текст", "*.txt *.md *.csv"), ("Усі файли", "*.*")])
        if path:
            self.plain.delete("1.0", "end")
            self.plain.insert("1.0", Path(path).read_text(encoding="utf-8", errors="replace"))

    def save_cipher(self):
        if not self.last_cipher:
            return
        path = filedialog.asksaveasfilename(defaultextension=".bin",
                                            filetypes=[("Двійковий файл", "*.bin"), ("Hex", "*.txt")])
        if path:
            if path.endswith(".txt"):
                Path(path).write_text(self.last_cipher.hex(), encoding="ascii")
            else:
                Path(path).write_bytes(self.last_cipher)

    def copy_cipher(self):
        self.clipboard_clear()
        self.clipboard_append(self.cipher_text.get("1.0", "end").strip())

    def read_cipher(self) -> bytes:
        raw = self.cipher_text.get("1.0", "end").strip()
        if self.fmt.get() == "hex":
            return _parse_hex(raw)
        try:
            return base64.b64decode(raw, validate=True)
        except binascii.Error as exc:
            raise ValueError("некоректний Base64") from exc

    # --- дії
    def encrypt(self):
        try:
            m = self.mode.get()
            cipher = self.cipher()
            iv = _parse_hex(self.iv.get()) if modes.MODE_INFO[m]["iv"] else b""
            data = self.plain.get("1.0", "end-1c").encode("utf-8")
            warn = []
            if m in ("CFB8", "CFB", "OFB", "CTR", "GCM"):
                marker = (_parse_hex(self.key.get()), iv, m)
                if marker in self.used_nonces:
                    warn.append("УВАГА: цей IV/nonce уже використано з тим самим ключем — "
                                "для потокових режимів це розкриває XOR відкритих текстів. "
                                "Згенеруйте новий.")
                self.used_nonces.add(marker)
            t0 = time.perf_counter()
            ct = modes.encrypt(m, cipher, iv, data, aad=self.aad.get().encode("utf-8"))
            dt = time.perf_counter() - t0
            self.show_cipher(ct)
            total, distinct = analysis.repeated_blocks(ct if m != "GCM" else ct[:-16])
            facts = [f"Зашифровано {len(data)} Б → {len(ct)} Б за {dt * 1000:.1f} мс."]
            if m == "ECB" and total:
                facts.append(f"Різних блоків шифротексту: {distinct} із {total}.")
            if m == "GCM":
                facts.append("Останні 16 байтів — тег автентичності.")
            elif m != "ECB":
                facts.append("Режим не має контролю цілісності: для передачі даних поєднуйте з HMAC або беріть GCM.")
            self.info.config(text=" ".join(facts + warn), foreground=WARN if warn else "#52514e")
        except ValueError as exc:
            messagebox.showerror("Помилка", str(exc))

    def decrypt(self):
        try:
            m = self.mode.get()
            iv = _parse_hex(self.iv.get()) if modes.MODE_INFO[m]["iv"] else b""
            data = modes.decrypt(m, self.cipher(), iv, self.read_cipher(),
                                 aad=self.aad.get().encode("utf-8"))
            self.plain.delete("1.0", "end")
            self.plain.insert("1.0", data.decode("utf-8", errors="replace"))
            self.info.config(text=f"Розшифровано {len(data)} Б.", foreground=OK)
        except modes.AuthenticationError:
            self.info.config(text="Тег GCM не збігся: шифротекст, AAD, ключ або nonce змінено. "
                                  "Розшифрований текст не видається.", foreground=WARN)
        except modes.PaddingError:
            self.info.config(text="Некоректне доповнення: ключ, IV або шифротекст не той.",
                             foreground=WARN)
        except ValueError as exc:
            messagebox.showerror("Помилка", str(exc))


class FileTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=16)
        self.app = app
        self.worker: threading.Thread | None = None
        self.columnconfigure(1, weight=1)
        ttk.Label(self, text="Шифрування файлів паролем", font=(UI_FAMILY, 12, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w")
        ttk.Label(self, text="Ключ виводиться з пароля через PBKDF2-HMAC-SHA256 із випадковою сіллю. "
                             "Цілісність перевіряється завжди: тег GCM або HMAC-SHA256.",
                  foreground="#52514e", wraplength=900).grid(row=1, column=0, columnspan=3,
                                                             sticky="w", pady=(2, 12))
        ttk.Label(self, text="Файл:").grid(row=2, column=0, sticky="w")
        self.path = tk.StringVar()
        ttk.Entry(self, textvariable=self.path).grid(row=2, column=1, sticky="ew", padx=4)
        ttk.Button(self, text="Огляд…", command=self.browse).grid(row=2, column=2)
        ttk.Label(self, text="Пароль:").grid(row=3, column=0, sticky="w", pady=6)
        self.password = tk.StringVar()
        pw_frame = ttk.Frame(self)
        pw_frame.grid(row=3, column=1, sticky="ew", padx=4)
        self.pw_entry = ttk.Entry(pw_frame, textvariable=self.password, show="•")
        self.pw_entry.pack(fill="x")
        self.strength = ttk.Label(pw_frame, foreground="#52514e")
        self.strength.pack(anchor="w")
        self.show = tk.BooleanVar()
        pw_tools = ttk.Frame(self)
        pw_tools.grid(row=3, column=2, sticky="w")
        ttk.Checkbutton(pw_tools, text="показати", variable=self.show,
                        command=lambda: self.pw_entry.config(show="" if self.show.get() else "•")
                        ).pack(side="left")
        ttk.Button(pw_tools, text="Згенерувати", command=self.generate_password).pack(side="left", padx=4)
        self.password.trace_add("write", lambda *_: self.update_strength())
        opts = ttk.Frame(self)
        opts.grid(row=4, column=0, columnspan=3, sticky="w", pady=6)
        ttk.Label(opts, text="Режим:").pack(side="left")
        self.mode = tk.StringVar(value="GCM")
        ttk.Combobox(opts, textvariable=self.mode, values=list(modes.MODES), width=8,
                     state="readonly").pack(side="left", padx=(4, 16))
        ttk.Label(opts, text="Ключ:").pack(side="left")
        self.key_len = tk.IntVar(value=32)
        for n in (16, 24, 32):
            ttk.Radiobutton(opts, text=f"{8 * n} біт", value=n, variable=self.key_len).pack(side="left")
        ttk.Label(opts, text="Ітерацій PBKDF2:").pack(side="left", padx=(16, 4))
        self.iterations = tk.IntVar(value=container.DEFAULT_ITERATIONS)
        ttk.Entry(opts, textvariable=self.iterations, width=9).pack(side="left")
        ttk.Label(opts, text="Реалізація:").pack(side="left", padx=(16, 4))
        default = "OpenSSL (cryptography)" if "OpenSSL (cryptography)" in IMPLEMENTATIONS \
            else "Таблична (T-таблиці)"
        self.impl = tk.StringVar(value=default)
        ttk.Combobox(opts, textvariable=self.impl, values=list(IMPLEMENTATIONS), width=24,
                     state="readonly").pack(side="left")
        row = ttk.Frame(self)
        row.grid(row=5, column=0, columnspan=3, sticky="w", pady=10)
        ttk.Button(row, text="Зашифрувати файл", style="Accent.TButton",
                   command=lambda: self.run(True)).pack(side="left")
        ttk.Button(row, text="Розшифрувати .aeslab", command=lambda: self.run(False)).pack(
            side="left", padx=8)
        ttk.Button(row, text="Відомості про файл", command=self.file_info).pack(side="left")
        self.progress = ttk.Progressbar(self, mode="indeterminate", length=300)
        self.progress.grid(row=6, column=0, columnspan=2, sticky="w")
        self.status = ttk.Label(self, wraplength=900, justify="left")
        self.status.grid(row=7, column=0, columnspan=3, sticky="w", pady=8)

    def browse(self):
        path = filedialog.askopenfilename()
        if path:
            self.path.set(path)

    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + "-_.!?"
        self.password.set("".join(secrets.choice(alphabet) for _ in range(20)))
        self.show.set(True)
        self.pw_entry.config(show="")

    @staticmethod
    def estimate_bits(pw: str) -> float:
        """Груба оцінка: довжина × log2(розмір використаних класів символів)."""
        pool = 0
        pool += 26 if any(c.islower() and c.isascii() for c in pw) else 0
        pool += 26 if any(c.isupper() and c.isascii() for c in pw) else 0
        pool += 10 if any(c.isdigit() for c in pw) else 0
        pool += 33 if any(not c.isalnum() and c.isascii() for c in pw) else 0
        pool += 66 if any(not c.isascii() for c in pw) else 0       # кирилиця тощо
        return len(pw) * math.log2(pool) if pool else 0.0

    def update_strength(self):
        bits = self.estimate_bits(self.password.get())
        level = ("слабкий" if bits < 50 else "помірний" if bits < 80 else "сильний")
        color = WARN if bits < 50 else ("#52514e" if bits < 80 else OK)
        self.strength.config(text=f"Оцінка пароля: ≈ {bits:.0f} біт — {level} "
                                  f"(груба оцінка за довжиною й класами символів)" if bits else "",
                             foreground=color)

    def file_info(self):
        path = Path(self.path.get())
        try:
            header, pos = container.read_header(path.read_bytes()[:256])
        except (OSError, container.ContainerError) as exc:
            self.status.config(text=f"Не файл AES Studio: {exc}", foreground=WARN)
            return
        tag = 16 if modes.MODE_INFO[header.mode]["auth"] else 32
        size = path.stat().st_size
        self.status.config(
            text=f"{path.name}: режим {header.mode}, ключ {8 * header.key_len} біт, PBKDF2 "
                 f"{header.iterations} ітерацій, сіль {header.salt.hex()}, IV/nonce {header.iv.hex() or '—'}; "
                 f"заголовок {pos} Б, дані {size - pos - tag} Б, "
                 f"{'тег GCM' if tag == 16 else 'HMAC-SHA256'} {tag} Б.",
            foreground="#52514e")

    def run(self, encrypt: bool):
        path, pw = Path(self.path.get()), self.password.get()
        if not path.is_file():
            messagebox.showerror("Помилка", "оберіть файл")
            return
        if not pw:
            messagebox.showerror("Помилка", "введіть пароль")
            return
        self.progress.start(12)
        self.status.config(text="Обробка…", foreground="#52514e")
        self.worker = threading.Thread(target=self._work, args=(encrypt, path, pw), daemon=True)
        self.worker.start()

    def _work(self, encrypt: bool, path: Path, pw: str):
        t0 = time.perf_counter()
        try:
            cls = IMPLEMENTATIONS[self.impl.get()]
            data = path.read_bytes()
            if encrypt:
                out = container.seal(data, pw, self.mode.get(), self.key_len.get(),
                                     int(self.iterations.get()), cipher_cls=cls)
                target = path.with_name(path.name + ".aeslab")
                msg = f"Збережено {target.name}: {len(data)} Б → {len(out)} Б"
            else:
                out, header = container.open_sealed(data, pw, cipher_cls=cls)
                name = path.name[:-7] if path.name.endswith(".aeslab") else path.name + ".dec"
                target = path.with_name(name)
                if target.exists():
                    target = target.with_name("розшифровано_" + target.name)
                msg = (f"Відновлено {target.name} ({len(out)} Б), режим {header.mode}, "
                       f"ключ {8 * header.key_len} біт")
            target.write_bytes(out)
            self.after(0, self._done, f"{msg}, {time.perf_counter() - t0:.2f} с.", OK)
        except (container.ContainerError, ValueError, OSError) as exc:
            self.after(0, self._done, f"Помилка: {exc}", WARN)

    def _done(self, text: str, color: str):
        self.progress.stop()
        self.status.config(text=text, foreground=color)


class ImageTab(ttk.Frame):
    SCALE = 2

    def __init__(self, master, app):
        super().__init__(master, padding=12)
        self.app = app
        w, h, px = demo_image.render()
        self.width, self.height, self.pixels = w, h, px
        bar = ttk.Frame(self)
        bar.pack(fill="x")
        ttk.Label(bar, text="Режим:").pack(side="left")
        self.mode = tk.StringVar(value="ECB")
        for m in ("ECB", "CBC", "CFB", "OFB", "CTR", "CTS", "GCM"):
            ttk.Radiobutton(bar, text=m, value=m, variable=self.mode,
                            command=self.refresh).pack(side="left", padx=4)
        ttk.Button(bar, text="Новий ключ", command=self.rekey).pack(side="left", padx=12)
        ttk.Button(bar, text="Відкрити зображення…", command=self.open_image).pack(side="left")
        ttk.Button(bar, text="Зберегти зашифроване…", command=self.save_image).pack(side="left", padx=6)
        frames = ttk.Frame(self)
        frames.pack(fill="both", expand=True, pady=10)
        self.left = ttk.Label(frames)
        self.left.pack(side="left", padx=8)
        self.right = ttk.Label(frames)
        self.right.pack(side="left", padx=8)
        self.caption = ttk.Label(self, wraplength=1000, justify="left")
        self.caption.pack(anchor="w")
        self.key, self.iv = os.urandom(16), os.urandom(16)
        self.refresh()

    def rekey(self):
        self.key, self.iv = os.urandom(16), os.urandom(16)
        self.refresh()

    def open_image(self):
        path = filedialog.askopenfilename(filetypes=[("Зображення", "*.png *.jpg *.jpeg *.bmp *.ppm")])
        if not path:
            return
        try:
            if path.lower().endswith(".ppm"):
                w, h, px = demo_image.from_ppm(Path(path).read_bytes())
            else:
                from PIL import Image
                im = Image.open(path).convert("RGB")
                im.thumbnail((256, 256))
                w, h, px = im.width, im.height, im.tobytes()
        except Exception as exc:  # noqa: BLE001 — показати користувачу будь-яку причину
            messagebox.showerror("Помилка", f"не вдалося відкрити: {exc}")
            return
        self.width, self.height, self.pixels = w, h, px
        self.refresh()

    def save_image(self):
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if path:
            self._right_img.write(path, format="png")

    def _photo(self, pixels: bytes) -> tk.PhotoImage:
        img = tk.PhotoImage(data=demo_image.to_ppm(self.width, self.height, pixels), format="PPM")
        return img.zoom(self.SCALE)

    def refresh(self):
        m = self.mode.get()
        cipher = IMPLEMENTATIONS["Таблична (T-таблиці)"](self.key)
        iv = self.iv[:12] if m == "GCM" else self.iv
        enc = analysis.encrypt_pixels(m, cipher, iv, self.pixels)
        self._left_img = self._photo(self.pixels)
        self._right_img = self._photo(enc)
        self.left.config(image=self._left_img)
        self.right.config(image=self._right_img)
        total, distinct = analysis.repeated_blocks(enc)
        p_total, p_distinct = analysis.repeated_blocks(self.pixels)
        self.caption.config(
            text=f"Зліва — оригінал ({self.width} × {self.height}), справа — пікселі після {m}. "
                 f"Різних блоків: в оригіналі {p_distinct} із {p_total}, у шифротексті {distinct} із {total}. "
                 + ("ECB зберігає повтори блоків, тому контури видно." if m == "ECB"
                    else "Повторів немає — зображення схоже на шум."),
            foreground=WARN if m == "ECB" else "#52514e")


class CompareTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=12)
        self.app = app
        cols = ("mode",) + tuple(f"p{i}" for i in range(len(analysis.PROPERTY_NAMES))) + ("speed", "error")
        ttk.Style(self).configure("Compare.Treeview.Heading", padding=(2, 6))
        ttk.Style(self).configure("Compare.Treeview", rowheight=26)
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=9,
                                 style="Compare.Treeview")
        heads = ("Режим", "Доповнення", "IV / nonce", "Паралельне шифр.",
                 "Паралельне розшифр.", "Довільний доступ", "Цілісність",
                 "КБ/с", "1 хибний біт →")
        widths = (60, 85, 240, 115, 130, 125, 80, 65, 130)
        for c, h, w in zip(cols, heads, widths):
            self.tree.heading(c, text=h)
            self.tree.column(c, width=w, anchor="center")
        for m in modes.MODES:
            self.tree.insert("", "end", iid=m, values=(m,) + analysis.PROPERTIES[m] + ("—", "—"))
        self.tree.pack(fill="x")
        ttk.Label(self, text="\n".join(analysis.PROPERTY_NOTES), foreground="#52514e",
                  wraplength=1100, justify="left").pack(anchor="w", pady=(6, 0))
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=8)
        ttk.Label(bar, text="Реалізація:").pack(side="left")
        self.impl = tk.StringVar(value="Таблична (T-таблиці)")
        ttk.Combobox(bar, textvariable=self.impl, values=list(IMPLEMENTATIONS), width=24,
                     state="readonly").pack(side="left", padx=4)
        ttk.Button(bar, text="Виміряти швидкість", command=self.measure).pack(side="left", padx=8)
        ttk.Button(bar, text="Інвертувати 1 біт шифротексту", command=self.propagate).pack(side="left")
        self.note = ttk.Label(self, foreground="#52514e", wraplength=1000, justify="left",
                              text="Поширення помилки: у 64-байтовому повідомленні інвертується "
                                   "перший біт другого блоку шифротексту; показано, скільки байтів "
                                   "відкритого тексту зіпсовано після розшифрування.")
        self.note.pack(anchor="w")
        self.chart = tk.Canvas(self, height=230, background="white", highlightthickness=0)
        self.chart.pack(fill="x", pady=(10, 0))
        self.speeds: dict[str, float] = {}

    def draw_chart(self):
        c = self.chart
        c.delete("all")
        if not self.speeds:
            return
        width = max(c.winfo_width(), 900)
        top = max(self.speeds.values())
        bar_w = (width - 120) / len(self.speeds)
        c.create_text(10, 12, anchor="w", text=f"Швидкість шифрування, КБ/с ({self.impl.get()})",
                      font=(UI_FAMILY, 10, "bold"))
        for i, (m, v) in enumerate(self.speeds.items()):
            x0 = 60 + i * bar_w + 10
            h = 160 * v / top
            color = OK if m == "GCM" else (WARN if m == "ECB" else ACCENT)
            c.create_rectangle(x0, 200 - h, x0 + bar_w - 20, 200, fill=color, outline="")
            c.create_text(x0 + (bar_w - 20) / 2, 192 - h, text=f"{v:,.0f}".replace(",", " "),
                          font=(UI_FAMILY, 9))
            c.create_text(x0 + (bar_w - 20) / 2, 214, text=m, font=(UI_FAMILY, 9))

    def _set(self, mode: str, column: str, value: str):
        self.tree.set(mode, column, value)

    def measure(self):
        cls = IMPLEMENTATIONS[self.impl.get()]
        threading.Thread(target=self._measure, args=(cls,), daemon=True).start()

    def _measure(self, cls):
        key, data = os.urandom(16), os.urandom(16 * 1024 if cls is not AES else 4 * 1024)
        cipher = cls(key)
        for m in modes.MODES:
            iv = os.urandom(modes.MODE_INFO[m]["iv"])
            t0 = time.perf_counter()
            modes.encrypt(m, cipher, iv, data)
            speed = len(data) / 1024 / (time.perf_counter() - t0)
            self.speeds[m] = speed
            self.after(0, self._set, m, "speed", f"{speed:,.0f}".replace(",", " "))
        self.after(0, self.draw_chart)

    def propagate(self):
        key, iv16 = os.urandom(16), os.urandom(16)
        msg = bytes(range(64))
        for m in modes.MODES:
            iv = iv16[:modes.MODE_INFO[m]["iv"]]
            res = analysis.error_propagation(m, key, iv, msg, bit=128)
            if res == "rejected":
                text = "зміну виявлено"
            elif res == "padding":
                text = "помилка доповнення"
            else:
                bad = [i for i, v in enumerate(res) if v]
                text = f"{len(bad)} Б ({sum(res)} біт)"
            self._set(m, "error", text)


class RoundsTab(ttk.Frame):
    def __init__(self, master, app):
        super().__init__(master, padding=12)
        self.app = app
        form = ttk.Frame(self)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="Ключ (hex):").grid(row=0, column=0, sticky="w")
        self.key = tk.StringVar(value="000102030405060708090a0b0c0d0e0f")
        ttk.Entry(form, textvariable=self.key, font=MONO).grid(row=0, column=1, sticky="ew", padx=4)
        ttk.Label(form, text="Блок (hex):").grid(row=1, column=0, sticky="w", pady=4)
        self.block = tk.StringVar(value="00112233445566778899aabbccddeeff")
        ttk.Entry(form, textvariable=self.block, font=MONO).grid(row=1, column=1, sticky="ew", padx=4)
        ttk.Label(form, text="Інвертувати біт №:").grid(row=2, column=0, sticky="w")
        self.bit = tk.IntVar(value=0)
        ttk.Spinbox(form, from_=0, to=127, textvariable=self.bit, width=6).grid(
            row=2, column=1, sticky="w", padx=4)
        ttk.Button(form, text="Показати раунди", style="Accent.TButton",
                   command=self.show).grid(row=0, column=2, rowspan=3, padx=8)
        self.text = tk.Text(self, font=MONO, height=22, wrap="none")
        self.text.pack(fill="both", expand=True, pady=8)
        ttk.Label(self, text="Побітова карта: кожен квадрат — 128 бітів стану (8 × 16); "
                             "помаранчеві клітинки — біти, що змінилися").pack(anchor="w")
        self.bits = tk.Canvas(self, height=86, background="white", highlightthickness=0)
        self.bits.pack(fill="x", pady=(4, 0))
        self.text.tag_configure("diff", background="#fde1d3", foreground="#7a2e0e")
        self.text.tag_configure("head", foreground=ACCENT, font=(MONO_FAMILY, 10, "bold"))
        self.show()

    def show(self):
        try:
            key, block = _parse_hex(self.key.get()), _parse_hex(self.block.get())
            if len(block) != 16:
                raise ValueError("блок має 16 байтів")
            a = AES(key).trace(block)
            b = AES(key).trace(analysis.flip_bit(block, int(self.bit.get()) % 128))
        except ValueError as exc:
            messagebox.showerror("Помилка", str(exc))
            return
        t = self.text
        t.delete("1.0", "end")
        t.insert("end", f"AES-{8 * len(key)}: стан після кожного раунду; підсвічено байти, "
                        f"що змінилися після інверсії біта {int(self.bit.get()) % 128} відкритого тексту\n\n")
        per_row = 4
        for start in range(0, len(a), per_row):
            idx = range(start, min(start + per_row, len(a)))
            heads = []
            for r in idx:
                name = "вхід ⊕ K0" if r == 0 else f"раунд {r}"
                heads.append(f"{name:<11}Δ = {analysis.hamming(a[r], b[r]):>3} біт")
            t.insert("end", "".join(f"{h:<30}" for h in heads) + "\n", "head")
            for row in range(4):
                for r in idx:
                    for col in range(4):
                        i = row + 4 * col
                        tag = "diff" if a[r][i] != b[r][i] else ""
                        t.insert("end", f"{a[r][i]:02x}", tag)
                        t.insert("end", " ")
                    t.insert("end", " " * 18)
                t.insert("end", "\n")
            t.insert("end", "\n")
        t.insert("end", f"Шифротекст: {bytes(a[-1]).hex()}")
        self.draw_bits(a, b)

    def draw_bits(self, a, b):
        c = self.bits
        c.delete("all")
        cell = 4
        for r, (sa, sb) in enumerate(zip(a, b)):
            x0 = 8 + r * (16 * cell + 12)
            diff = int.from_bytes(bytes(sa), "big") ^ int.from_bytes(bytes(sb), "big")
            for k in range(128):
                row, col = divmod(k, 16)
                on = (diff >> (127 - k)) & 1
                c.create_rectangle(x0 + col * cell, 6 + row * cell, x0 + col * cell + cell - 1,
                                   6 + row * cell + cell - 1, outline="",
                                   fill="#eb6834" if on else "#ecebe7")
            c.create_text(x0 + 8 * cell, 6 + 8 * cell + 12, text=str(r), font=(UI_FAMILY, 8))


class SBoxTab(ttk.Frame):
    """S-блок AES: таблиця, обернений елемент і критерії стійкості."""

    CELL = 34

    def __init__(self, master, app):
        super().__init__(master, padding=12)
        self.app = app
        ttk.Label(self, text="S-блок AES: S(a) = A·a⁻¹ ⊕ 63 у полі GF(2⁸)",
                  font=(UI_FAMILY, 12, "bold")).pack(anchor="w")
        body = ttk.Frame(self)
        body.pack(fill="both", expand=True, pady=8)
        size = self.CELL * 17
        self.canvas = tk.Canvas(body, width=size, height=size, background="white", highlightthickness=0)
        self.canvas.pack(side="left")
        self.canvas.bind("<Button-1>", self.on_click)
        side = ttk.Frame(body, padding=(16, 0))
        side.pack(side="left", fill="both", expand=True)
        self.detail = ttk.Label(side, font=MONO, justify="left")
        self.detail.pack(anchor="w")
        props = analysis.sbox_properties()
        ttk.Label(side, text="Критерії стійкості (обчислено з таблиці):",
                  font=(UI_FAMILY, 10, "bold")).pack(anchor="w", pady=(16, 4))
        hist = ", ".join(f"{v}×{k}" for k, v in props["ddt_histogram"].items())
        ttk.Label(side, justify="left", wraplength=480, text=(
            f"• диференційна рівномірність: {props['differential_uniformity']} "
            f"(найбільша ймовірність диференціала {props['differential_uniformity']}/256 = 2⁻⁶);\n"
            f"• нелінійність: {props['nonlinearity']} (найбільше лінійне зміщення "
            f"{props['max_linear_bias']}/256);\n"
            f"• алгебраїчний степінь компонент: {props['algebraic_degree']};\n"
            f"• нерухомих точок S(a) = a: {props['fixed_points']}, "
            f"S(a) = a ⊕ ff: {props['opposite_fixed_points']};\n"
            f"• таблиця різниць (a ≠ 0): {hist}.")).pack(anchor="w")
        self.selected = 0x53
        self.draw()
        self.select(self.selected)

    def draw(self):
        c, n = self.canvas, self.CELL
        c.delete("all")
        for i in range(16):
            c.create_text(n * (i + 1.5), n / 2, text=f"{i:x}", font=(MONO_FAMILY, 10, "bold"), fill=ACCENT)
            c.create_text(n / 2, n * (i + 1.5), text=f"{i:x}", font=(MONO_FAMILY, 10, "bold"), fill=ACCENT)
        for a in range(256):
            row, col = divmod(a, 16)
            x0, y0 = n * (col + 1), n * (row + 1)
            fill = "#fde1d3" if a == self.selected else ("#f6f5f1" if (row + col) % 2 else "white")
            c.create_rectangle(x0, y0, x0 + n, y0 + n, fill=fill, outline="#e3e2de")
            c.create_text(x0 + n / 2, y0 + n / 2, text=f"{SBOX[a]:02x}", font=(MONO_FAMILY, 10))

    def on_click(self, event):
        col, row = int(event.x // self.CELL) - 1, int(event.y // self.CELL) - 1
        if 0 <= row < 16 and 0 <= col < 16:
            self.select(16 * row + col)

    def select(self, a: int):
        from .aes import gmul
        self.selected = a
        self.draw()
        inv = next((b for b in range(1, 256) if gmul(a, b) == 1), 0)
        s = SBOX[a]
        self.detail.config(text=(
            f"a        = {a:02x}  ({a:08b})\n"
            f"a⁻¹      = {inv:02x}  ({inv:08b})   обернений у GF(2⁸)\n"
            f"S(a)     = {s:02x}  ({s:08b})   після афінного перетворення\n"
            f"S⁻¹(a)   = {INV_SBOX[a]:02x}\n"
            f"S(a) ⊕ a = {s ^ a:02x}  ({bin(s ^ a).count('1')} біт відрізняються)"))


class AESStudio(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES Studio — ЛР9 «Захист даних»")
        self.geometry("1180x760")
        self.minsize(1000, 640)
        style = ttk.Style(self)
        for theme in ("vista", "aqua", "clam"):        # Windows, macOS, Linux
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Accent.TButton", font=(UI_FAMILY, 10, "bold"))
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=8)
        self.tabs = {}
        for name, cls in (("Текст", TextTab), ("Файли", FileTab), ("Зображення", ImageTab),
                          ("Порівняння режимів", CompareTab), ("Раунди AES", RoundsTab),
                          ("S-блок", SBoxTab)):
            tab = cls(self.notebook, self)
            self.notebook.add(tab, text=name)
            self.tabs[name] = tab
        footer = ttk.Label(self, text="Власні реалізації AES (FIPS-197) і режимів SP 800-38A/38D · "
                                      "github.com/RE22GDV/LR9-AES", foreground="#8a8984")
        footer.pack(anchor="e", padx=10, pady=(0, 6))


def _dpi_aware():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass


def screenshots(app: AESStudio, out_dir: Path) -> None:
    """Зберегти знімки вкладок (потрібен Pillow; Windows, macOS або Linux з X11)."""
    from PIL import ImageGrab

    out_dir.mkdir(parents=True, exist_ok=True)
    text = app.tabs["Текст"]
    compare = app.tabs["Порівняння режимів"]
    files = app.tabs["Файли"]
    sample = Path.cwd() / "приклад.txt"          # без особистого шляху на знімку
    sample.write_text("Конфіденційні дані лабораторної роботи №9.\n" * 2000, encoding="utf-8")

    def encrypt_sample():
        files.path.set(str(sample))
        files.generate_password()
        files.run(True)
        while files.worker.is_alive():          # не join(): потік звертається до Tk
            app.update()
            time.sleep(0.05)
        app.update()

    def text_demo():
        text.mode.set("ECB")
        text.on_mode()
        text.plain.delete("1.0", "end")
        line = "Звіт за жовтень: ДОХІД 100 000 UAH."
        while (len(line.encode("utf-8")) + 1) % 16:      # рядок займає ціле число блоків
            line += " "
        text.plain.insert("1.0", (line + "\n") * 4 + "Однакові рядки → однакові блоки (ECB).")
        text.encrypt()

    def compare_demo():
        compare.propagate()
        compare._measure(IMPLEMENTATIONS["Таблична (T-таблиці)"])
        app.update()
        compare.draw_chart()

    plan = [
        ("Текст", "gui_text.png", text_demo),
        ("Зображення", "gui_image.png", lambda: None),
        ("Порівняння режимів", "gui_compare.png", compare_demo),
        ("Раунди AES", "gui_rounds.png", lambda: None),
        ("S-блок", "gui_sbox.png", lambda: None),
        ("Файли", "gui_files.png", encrypt_sample),
    ]
    for tab, name, action in plan:
        app.notebook.select(app.tabs[tab])
        action()
        app.update()
        time.sleep(0.6)
        app.update()
        x, y = app.winfo_rootx(), app.winfo_rooty()
        w, h = app.winfo_width(), app.winfo_height()
        ImageGrab.grab(bbox=(x, y, x + w, y + h)).save(out_dir / name)
        print("знімок ->", out_dir / name)
    for leftover in (sample, sample.with_name(sample.name + ".aeslab")):
        leftover.unlink(missing_ok=True)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    _dpi_aware()
    app = AESStudio()
    if "--screenshot" in argv:
        out = Path(argv[argv.index("--screenshot") + 1])
        app.attributes("-topmost", True)
        app.after(800, lambda: (screenshots(app, out), app.destroy()))
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
