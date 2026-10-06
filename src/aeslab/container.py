"""Формат зашифрованого файла програми AES Studio («.aeslab»).

Ключ виводиться з пароля функцією PBKDF2-HMAC-SHA256 з випадковою сіллю.
Цілісність забезпечується завжди:

* GCM — власний тег автентичності (заголовок файла — додаткові дані AAD);
* решта режимів — схема «зашифрувати, потім обчислити MAC»: HMAC-SHA256
  від заголовка й шифротексту з окремим ключем, виведеним тим самим PBKDF2.

Структура (усі числа — big-endian):

    magic "AESLAB1\\n" (8) | режим (1) | довжина ключа в байтах (1)
    | ітерацій PBKDF2 (4) | сіль (16) | довжина IV/nonce (1) | IV/nonce
    | шифротекст | тег GCM (16) або HMAC-SHA256 (32)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from . import modes
from .aes_fast import FastAES

MAGIC = b"AESLAB1\n"
MODE_IDS = {name: i for i, name in enumerate(modes.MODES, start=1)}
MODE_BY_ID = {i: name for name, i in MODE_IDS.items()}
DEFAULT_ITERATIONS = 600_000          # рекомендація OWASP для PBKDF2-HMAC-SHA256


class ContainerError(ValueError):
    """Файл пошкоджено, змінено або пароль неправильний."""


@dataclass
class Header:
    mode: str
    key_len: int
    iterations: int
    salt: bytes
    iv: bytes

    def pack(self) -> bytes:
        return (MAGIC + struct.pack(">BBI", MODE_IDS[self.mode], self.key_len, self.iterations)
                + self.salt + struct.pack(">B", len(self.iv)) + self.iv)


def derive_keys(password: str, salt: bytes, iterations: int, key_len: int, mode: str):
    """Ключ шифрування і (для режимів без автентифікації) ключ HMAC."""
    mac_len = 0 if modes.MODE_INFO[mode]["auth"] else 32
    material = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                   iterations, key_len + mac_len)
    return material[:key_len], material[key_len:]


def seal(data: bytes, password: str, mode: str = "GCM", key_len: int = 32,
         iterations: int = DEFAULT_ITERATIONS, cipher_cls=FastAES) -> bytes:
    if mode not in MODE_IDS:
        raise ValueError(f"невідомий режим {mode!r}")
    if mode == "CTS" and len(data) < 16:
        raise ValueError("CTS потребує щонайменше 16 байтів")
    iv = os.urandom(modes.MODE_INFO[mode]["iv"])
    header = Header(mode, key_len, iterations, os.urandom(16), iv)
    enc_key, mac_key = derive_keys(password, header.salt, iterations, key_len, mode)
    head = header.pack()
    body = modes.encrypt(mode, cipher_cls(enc_key), iv, data, aad=head)
    if mac_key:
        body += hmac.new(mac_key, head + body, hashlib.sha256).digest()
    return head + body


def read_header(blob: bytes) -> tuple[Header, int]:
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 23:
        raise ContainerError("це не файл AES Studio")
    pos = len(MAGIC)
    mode_id, key_len, iterations = struct.unpack(">BBI", blob[pos:pos + 6])
    pos += 6
    salt = blob[pos:pos + 16]
    pos += 16
    iv_len = blob[pos]
    pos += 1
    iv = blob[pos:pos + iv_len]
    pos += iv_len
    if mode_id not in MODE_BY_ID or key_len not in (16, 24, 32) or len(iv) != iv_len:
        raise ContainerError("пошкоджений заголовок")
    return Header(MODE_BY_ID[mode_id], key_len, iterations, salt, iv), pos


def open_sealed(blob: bytes, password: str, cipher_cls=FastAES) -> tuple[bytes, Header]:
    header, pos = read_header(blob)
    head, body = blob[:pos], blob[pos:]
    enc_key, mac_key = derive_keys(password, header.salt, header.iterations,
                                   header.key_len, header.mode)
    if mac_key:
        body, tag = body[:-32], body[-32:]
        expected = hmac.new(mac_key, head + body, hashlib.sha256).digest()
        if len(tag) != 32 or not hmac.compare_digest(tag, expected):
            raise ContainerError("перевірка HMAC не пройдена: файл змінено або пароль хибний")
    try:
        return modes.decrypt(header.mode, cipher_cls(enc_key), header.iv, body, aad=head), header
    except (modes.AuthenticationError, modes.PaddingError) as exc:
        raise ContainerError("файл змінено або пароль хибний") from exc
