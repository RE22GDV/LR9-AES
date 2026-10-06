"""Реалізації блочного шифру, з яких можна обирати в програмі та тестах."""

from __future__ import annotations

from .aes import AES
from .aes_fast import FastAES


class OpenSSLAES:
    """Обгортка AES з бібліотеки cryptography (OpenSSL) — еталон для звірки."""

    block_size = 16

    def __init__(self, key: bytes):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        cipher = Cipher(algorithms.AES(bytes(key)), modes.ECB())
        self._enc = cipher.encryptor()
        self._dec = cipher.decryptor()

    def encrypt_block(self, block: bytes) -> bytes:
        return self._enc.update(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._dec.update(block)


def openssl_available() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


IMPLEMENTATIONS = {
    "Еталонна (FIPS-197)": AES,
    "Таблична (T-таблиці)": FastAES,
}
if openssl_available():
    IMPLEMENTATIONS["OpenSSL (cryptography)"] = OpenSSLAES
