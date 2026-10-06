"""Командний інтерфейс: ``python run.py <команда>``."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import container, modes
from .backends import IMPLEMENTATIONS

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "tests" / "vectors.json"


def check_vector(v: dict, cipher_cls) -> bool:
    cipher = cipher_cls(bytes.fromhex(v["key"]))
    pt, ct = bytes.fromhex(v["plaintext"]), bytes.fromhex(v["ciphertext"])
    iv = bytes.fromhex(v.get("iv", ""))
    mode = v["mode"]
    if mode == "BLOCK":
        return cipher.encrypt_block(pt) == ct and cipher.decrypt_block(ct) == pt
    if mode == "GCM":
        aad, tag = bytes.fromhex(v["aad"]), bytes.fromhex(v["tag"])
        got = modes.encrypt("GCM", cipher, iv, pt, aad)
        return got == ct + tag and modes.decrypt("GCM", cipher, iv, got, aad) == pt
    if mode in ("ECB", "CBC"):
        enc = (modes.ecb_encrypt(cipher, pt, pad=False) if mode == "ECB"
               else modes.cbc_encrypt(cipher, iv, pt, pad=False))
        dec = (modes.ecb_decrypt(cipher, ct, pad=False) if mode == "ECB"
               else modes.cbc_decrypt(cipher, iv, ct, pad=False))
        return enc == ct and dec == pt
    return modes.encrypt(mode, cipher, iv, pt) == ct and modes.decrypt(mode, cipher, iv, ct) == pt


def cmd_selftest(_args) -> int:
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]
    failures = 0
    for name, cls in IMPLEMENTATIONS.items():
        ok = sum(check_vector(v, cls) for v in vectors)
        failures += len(vectors) - ok
        print(f"[{'OK' if ok == len(vectors) else 'FAIL'}] {name}: {ok} з {len(vectors)} офіційних векторів")
    print("пройдено все" if failures == 0 else f"FAIL: {failures}")
    return 0 if failures == 0 else 1


def _password(args) -> str:
    return args.password if args.password is not None else getpass.getpass("Пароль: ")


def cmd_encrypt(args) -> int:
    data = Path(args.file).read_bytes()
    out = container.seal(data, _password(args), args.mode, args.key_bits // 8, args.iterations)
    target = Path(args.output or args.file + ".aeslab")
    target.write_bytes(out)
    print(f"{args.file} → {target} ({len(data)} Б → {len(out)} Б, {args.mode}, {args.key_bits} біт)")
    return 0


def cmd_decrypt(args) -> int:
    blob = Path(args.file).read_bytes()
    try:
        data, header = container.open_sealed(blob, _password(args))
    except container.ContainerError as exc:
        print(f"не розшифровано: {exc}", file=sys.stderr)
        return 1
    name = args.file[:-7] if args.file.endswith(".aeslab") else args.file + ".dec"
    target = Path(args.output or name)
    target.write_bytes(data)
    print(f"{args.file} → {target} ({len(data)} Б, {header.mode}, {8 * header.key_len} біт)")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["gui"]:                     # параметри програми передаються як є
        from .gui import main as gui_main
        return gui_main(argv[1:])
    parser = argparse.ArgumentParser(prog="aeslab", description="AES і режими шифрування (ЛР9)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("selftest", help="офіційні тестові вектори").set_defaults(fn=cmd_selftest)
    for name, fn in (("encrypt", cmd_encrypt), ("decrypt", cmd_decrypt)):
        p = sub.add_parser(name, help=f"{'зашифрувати' if name == 'encrypt' else 'розшифрувати'} файл паролем")
        p.add_argument("file")
        p.add_argument("-o", "--output")
        p.add_argument("-p", "--password", help="пароль (інакше буде запитано)")
        if name == "encrypt":
            p.add_argument("--mode", default="GCM", choices=list(modes.MODES))
            p.add_argument("--key-bits", type=int, default=256, choices=[128, 192, 256])
            p.add_argument("--iterations", type=int, default=container.DEFAULT_ITERATIONS)
        p.set_defaults(fn=fn)
    sub.add_parser("gui", help="програма AES Studio (параметр --screenshot DIR — знімки вкладок)")
    args = parser.parse_args(argv)
    return args.fn(args)
