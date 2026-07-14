#!/usr/bin/env python3
"""Print the current 6-digit SHA-256 TOTP for a Base32 seed."""

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


def generate_totp(seed: str, timestamp: int | float | None = None) -> str:
    current_time = time.time() if timestamp is None else float(timestamp)
    if current_time < 0:
        raise ValueError("timestamp must not be negative")

    key = decode_seed(normalize_seed(seed))
    counter = int(current_time) // 30
    digest = hmac.new(
        key,
        struct.pack(">Q", counter),
        hashlib.sha256,
    ).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def read_seed(argument: str | None) -> str:
    if argument is not None:
        return argument
    if sys.stdin.isatty():
        return getpass.getpass("Seed: ")
    return sys.stdin.readline()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the current 6-digit SHA-256 TOTP. "
            "On success, stdout contains only the code."
        )
    )
    parser.add_argument(
        "seed",
        nargs="?",
        help="Base32 seed or otpauth:// URI; stdin is used when omitted",
    )
    parser.add_argument(
        "--timestamp",
        type=float,
        default=None,
        help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code = generate_totp(read_seed(args.seed), args.timestamp)
    except (EOFError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1

    print(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
