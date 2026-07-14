#!/usr/bin/env python3
"""Continuously display the current 6-digit SHA-256 TOTP and remaining time."""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import struct
import sys
import time
import urllib.parse

ALGORITHM = hashlib.sha256
DIGITS = 6
PERIOD = 30
BASE32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def normalize_seed(value: str) -> str:
    seed = value.strip()
    if seed.lower().startswith("otpauth://"):
        parsed = urllib.parse.urlsplit(seed)
        values = urllib.parse.parse_qs(parsed.query).get("secret")
        if not values:
            raise ValueError("otpauth URI does not contain a secret")
        seed = values[0]

    normalized = "".join(seed.split()).replace("-", "").rstrip("=").upper()
    if not normalized:
        raise ValueError("seed is empty")
    if not set(normalized) <= BASE32_ALPHABET:
        raise ValueError("seed must be Base32")
    return normalized


def decode_seed(seed: str) -> bytes:
    padded = seed + "=" * ((8 - len(seed) % 8) % 8)
    try:
        decoded = base64.b32decode(padded, casefold=False)
    except binascii.Error as exc:
        raise ValueError("seed is not valid Base32") from exc
    if not decoded:
        raise ValueError("seed is empty")
    return decoded


def generate_totp(key: bytes, timestamp: int | float | None = None) -> str:
    current_time = time.time() if timestamp is None else float(timestamp)
    if current_time < 0:
        raise ValueError("timestamp must not be negative")

    counter = int(current_time) // PERIOD
    digest = hmac.new(
        key,
        struct.pack(">Q", counter),
        ALGORITHM,
    ).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % (10 ** DIGITS):0{DIGITS}d}"


def read_seed(argument: str | None) -> str:
    if argument is not None:
        return argument
    if sys.stdin.isatty():
        return getpass.getpass("Seed: ")
    return sys.stdin.readline()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Continuously display the current 6-digit SHA-256 TOTP "
            "and seconds remaining. Stop with Ctrl+C."
        )
    )
    parser.add_argument(
        "seed",
        nargs="?",
        help="Base32 seed or otpauth:// URI; stdin is used when omitted",
    )
    return parser


def render(code: str, remaining: int) -> None:
    text = f"TOTP: {code}  残り {remaining:2d}秒"
    if sys.stdout.isatty():
        print(f"\r\033[2K{text}", end="", flush=True)
    else:
        print(text, flush=True)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        key = decode_seed(normalize_seed(read_seed(args.seed)))
    except (EOFError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1

    try:
        while True:
            now = time.time()
            code = generate_totp(key, now)
            remaining = PERIOD - (int(now) % PERIOD)
            render(code, remaining)
            time.sleep(max(0.05, 1.0 - (time.time() % 1.0)))
    except KeyboardInterrupt:
        if sys.stdout.isatty():
            print()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
