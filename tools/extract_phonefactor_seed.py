#!/usr/bin/env python3
"""Print only the Base32 OATH seed from a PhoneFactor activation response."""

from __future__ import annotations

import argparse
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass

PHONEFACTOR_NAMESPACE = "http://www.phonefactor.com/PfPaWs"
SOAP_NAMESPACE = "http://schemas.xmlsoap.org/soap/envelope/"
DEFAULT_VERSION = "6.2509.6046"
BASE32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


@dataclass(frozen=True)
class ActivationParameters:
    url: str
    code: str


def first_query_value(query: dict[str, list[str]], *names: str) -> str | None:
    lowered = {key.lower(): values for key, values in query.items()}
    for name in names:
        values = lowered.get(name.lower())
        if values:
            value = values[0].strip()
            if value:
                return value
    return None


def parse_activation_parameters(
    activation_uri: str | None,
    url: str | None,
    code: str | None,
) -> ActivationParameters:
    parsed_url = url.strip() if url else None
    parsed_code = code.strip() if code else None

    if activation_uri:
        parsed = urllib.parse.urlsplit(activation_uri.strip())
        if (
            parsed.scheme.lower() != "phonefactor"
            or parsed.netloc.lower() != "activate_account"
        ):
            raise ValueError(
                "activation URI must start with phonefactor://activate_account"
            )

        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=False)
        parsed_url = parsed_url or first_query_value(
            query,
            "url",
            "activation_url",
            "activationurl",
        )
        parsed_code = parsed_code or first_query_value(
            query,
            "code",
            "activation_code",
            "activationcode",
        )

    if not parsed_url or not parsed_code:
        raise ValueError(
            "provide a phonefactor activation URI, or both --url and --code"
        )

    endpoint = urllib.parse.urlsplit(parsed_url)
    if endpoint.scheme.lower() != "https" or not endpoint.netloc:
        raise ValueError("the activation URL must be an HTTPS URL")
    if not parsed_code.isdecimal():
        raise ValueError("the activation code must contain decimal digits only")

    return ActivationParameters(url=parsed_url.rstrip("/"), code=parsed_code)


def build_endpoint(url: str) -> str:
    if url.lower().rstrip("/").endswith("/pfpaws.asmx"):
        return url.rstrip("/")
    return f"{url.rstrip('/')}/PfPaWs.asmx"


def build_request_xml(
    code: str,
    device_token: str,
    device_name: str,
    oath_counter: int,
    version: str,
) -> bytes:
    ET.register_namespace("soap", SOAP_NAMESPACE)
    ET.register_namespace("pf", PHONEFACTOR_NAMESPACE)

    envelope = ET.Element(f"{{{SOAP_NAMESPACE}}}Envelope")
    ET.SubElement(envelope, f"{{{SOAP_NAMESPACE}}}Header")
    body = ET.SubElement(envelope, f"{{{SOAP_NAMESPACE}}}Body")
    activate = ET.SubElement(body, f"{{{PHONEFACTOR_NAMESPACE}}}ActivateNew")
    parameters = ET.SubElement(
        activate,
        f"{{{PHONEFACTOR_NAMESPACE}}}activationParams",
    )

    values = {
        "ActivationCode": code,
        "DeviceToken": device_token,
        "DeviceName": device_name,
        "OathCounter": str(oath_counter),
        "Version": version,
    }
    for name, value in values.items():
        ET.SubElement(
            parameters,
            f"{{{PHONEFACTOR_NAMESPACE}}}{name}",
        ).text = value

    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


def element_text_by_local_name(root: ET.Element, name: str) -> str | None:
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == name and element.text:
            value = element.text.strip()
            if value:
                return value
    return None


def normalize_seed(value: str) -> str:
    seed = "".join(value.split()).replace("-", "").rstrip("=").upper()
    if not seed or not set(seed) <= BASE32_ALPHABET:
        raise ValueError("PhoneFactor returned an invalid Base32 seed")
    return seed


def parse_seed(response_xml: bytes) -> str:
    try:
        root = ET.fromstring(response_xml)
    except ET.ParseError as exc:
        raise ValueError("PhoneFactor returned invalid XML") from exc

    secret = element_text_by_local_name(root, "OathTokenSecretKey")
    if secret:
        return normalize_seed(secret)

    code = element_text_by_local_name(root, "Code")
    description = element_text_by_local_name(root, "Description")
    detail = description or (f"error code {code}" if code else "no seed in response")
    raise ValueError(f"PhoneFactor activation failed: {detail}")


def request_seed(
    parameters: ActivationParameters,
    device_token: str,
    device_name: str,
    oath_counter: int,
    version: str,
    timeout: float,
) -> str:
    request = urllib.request.Request(
        build_endpoint(parameters.url),
        data=build_request_xml(
            code=parameters.code,
            device_token=device_token,
            device_name=device_name,
            oath_counter=oath_counter,
            version=version,
        ),
        method="POST",
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": f"{PHONEFACTOR_NAMESPACE}/ActivateNew",
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 13; SIT-TOTP-AutoFill)",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return parse_seed(response.read())
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"PhoneFactor returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"PhoneFactor request failed: {exc.reason}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Extract a Base32 OATH seed from a PhoneFactor activation URI. "
            "On success, stdout contains only the seed."
        )
    )
    parser.add_argument(
        "activation_uri",
        nargs="?",
        help="phonefactor://activate_account?... URI",
    )
    parser.add_argument("--url", help="PhoneFactor activation base URL")
    parser.add_argument("--code", help="PhoneFactor activation code")
    parser.add_argument(
        "--device-token",
        default=None,
        help="device token; a random value is used when omitted",
    )
    parser.add_argument(
        "--device-name",
        default="SIT-TOTP-AutoFill",
        help="device name sent to PhoneFactor",
    )
    parser.add_argument(
        "--oath-counter",
        type=int,
        default=None,
        help="30-second Unix counter; current time is used when omitted",
    )
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--timeout", type=float, default=20.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        parameters = parse_activation_parameters(
            args.activation_uri,
            args.url,
            args.code,
        )
        if args.timeout <= 0:
            raise ValueError("--timeout must be greater than zero")

        oath_counter = (
            args.oath_counter
            if args.oath_counter is not None
            else int(time.time()) // 30
        )
        if oath_counter < 0:
            raise ValueError("--oath-counter must not be negative")

        seed = request_seed(
            parameters=parameters,
            device_token=args.device_token or secrets.token_urlsafe(48),
            device_name=args.device_name,
            oath_counter=oath_counter,
            version=args.version,
            timeout=args.timeout,
        )
    except (ValueError, RuntimeError) as exc:
        print(exc, file=sys.stderr)
        return 1

    print(seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
