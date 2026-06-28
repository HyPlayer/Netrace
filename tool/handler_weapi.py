#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from mitmproxy import http

from tool.aegis_mitm_core import text_preview
from tool.mitm_context import MitmContext
from tool.protocols import BaseProtocolHandler


CORE_JS_RE = re.compile(
    r"^https?://[^/?#]+\.music\.(?:126|163)\.net/web/s/core_[^/?#]+(?:\?[^#]*)?(?:#.*)?$",
    re.IGNORECASE,
)
RSA_KEY_PAIR_RE = re.compile(
    r"new\s+RSAKeyPair\s*\(\s*"
    r"(?P<exp>([A-Za-z_$][\w$]*)|(?:'[^']*')|(?:\"[^\"]*\"))\s*,\s*"
    r"(?P<empty>(?:'[^']*')|(?:\"[^\"]*\"))\s*,\s*"
    r"(?P<mod>([A-Za-z_$][\w$]*)|(?:'[^']*')|(?:\"[^\"]*\"))\s*\)",
)
DEFAULT_WEAPI_PRIVATE_KEY_FILE = Path(__file__).resolve().parent / "weapi-rsa-private.key"
WEAPI_PRESET_KEY = b"0CoJUm6Qyw8W8jud"
WEAPI_IV = b"0102030405060708"
WEAPI_SERVER_EXPONENT_HEX = "010001"
WEAPI_SERVER_MODULUS_HEX = (
    "00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417"
    "629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575"
    "cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7"
)


class WeapiHandler(BaseProtocolHandler):
    name = "weapi"

    def matches_request(self, flow: http.HTTPFlow) -> bool:
        return "/weapi/" in flow.request.path or _is_core_js_url(flow.request.pretty_url)

    def is_key_flow(self, flow: http.HTTPFlow, ctx: MitmContext) -> bool:
        return _is_core_js_url(flow.request.pretty_url)

    def handle_key_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        flow.metadata["netrace_protocol"] = self.name
        flow.metadata["netrace_key_handler"] = self.name
        self._ensure_key(ctx)
        ctx.emit_event(
            "key-request",
            flow,
            protocol=self.name,
            operation="key-request",
            key_flow=True,
            status="core-js",
            weapi_exponent=ctx.weapi_exponent_hex,
            weapi_modulus=ctx.weapi_modulus_hex,
        )

    def handle_key_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        if flow.response is None:
            return
        self._ensure_key(ctx)
        raw = flow.response.content
        text = raw.decode("utf-8", errors="replace")
        replacement = f'new RSAKeyPair("{ctx.weapi_exponent_hex}", "", "{ctx.weapi_modulus_hex}")'
        rewritten, count = RSA_KEY_PAIR_RE.subn(replacement, text, count=1)
        if count <= 0:
            dump_path = ctx.dump(flow, "weapi-key-rewrite-failed", raw)
            ctx.emit_event(
                "key-response-failed",
                flow,
                protocol=self.name,
                operation="key-response",
                key_flow=True,
                status="RSAKeyPair pattern not found",
                detail=text_preview(raw[:1000]),
                dump_path=str(dump_path) if dump_path else None,
            )
            return
        flow.response.content = rewritten.encode("utf-8")
        flow.response.headers["content-length"] = str(len(flow.response.content))
        ctx.emit_event(
            "key-response",
            flow,
            protocol=self.name,
            operation="key-response",
            key_flow=True,
            status="rsa-key-rewritten",
            weapi_exponent=ctx.weapi_exponent_hex,
            weapi_modulus=ctx.weapi_modulus_hex,
            replacements=count,
        )

    def handle_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        flow.metadata["netrace_protocol"] = self.name
        flow.metadata["aegis_protocol"] = self.name
        self._ensure_key(ctx)
        content_type = flow.request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            ctx.emit_event(
                "miss",
                flow,
                protocol=self.name,
                operation="miss",
                status=f"unexpected weapi content-type: {content_type or '<empty>'}",
            )
            return
        raw_request = flow.request.content
        values = urllib.parse.parse_qs(raw_request.decode("utf-8", errors="replace"), keep_blank_values=True)
        params = _first(values, "params")
        enc_sec_key = _first(values, "encSecKey")
        if not params or not enc_sec_key:
            ctx.emit_event(
                "decrypt-failed",
                flow,
                protocol=self.name,
                operation="decrypt-failed",
                status="weapi: missing params or encSecKey",
            )
            return
        try:
            aes_key, plain = self._decrypt_request_payload(ctx, params, enc_sec_key)
        except Exception as exc:
            ctx.emit_event(
                "decrypt-failed",
                flow,
                protocol=self.name,
                operation="decrypt-failed",
                status=f"weapi: {exc}",
            )
            return

        values["encSecKey"] = [rsa_encrypt_no_padding_hex(aes_key[::-1], WEAPI_SERVER_EXPONENT_HEX, WEAPI_SERVER_MODULUS_HEX)]
        rewritten = urllib.parse.urlencode(values, doseq=True).encode("utf-8")
        flow.request.content = rewritten
        flow.request.headers["content-length"] = str(len(rewritten))
        flow.metadata["aegis_mitm_hit"] = True
        flow.metadata["aegis_protocol"] = self.name
        flow.metadata["netrace_protocol"] = self.name
        raw_dump_path = ctx.dump(flow, "weapi-request-raw", raw_request)
        dump_path = ctx.dump(flow, "weapi-request", plain)
        body_text, body_format = _payload_text(plain)
        ctx.emit_event(
            "request",
            flow,
            protocol=self.name,
            operation="request",
            status="weapi-decrypted",
            detail=text_preview(plain),
            body=body_text,
            body_format=body_format,
            raw_detail=text_preview(raw_request[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
            session_key=aes_key.decode("utf-8", errors="replace"),
            server_enc_sec_key=values["encSecKey"][0],
            dump_path=str(dump_path) if dump_path else None,
        )

    def handle_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        if flow.response is None:
            return
        raw_dump_path = ctx.dump(flow, "weapi-response-raw", flow.response.content)
        body_text, body_format = _payload_text(flow.response.content)
        ctx.emit_event(
            "response",
            flow,
            protocol=self.name,
            operation="response",
            status="weapi-passthrough",
            content_type=flow.response.headers.get("content-type", ""),
            content_encoding=flow.response.headers.get("content-encoding", ""),
            body_len=len(flow.response.content),
            detail=text_preview(flow.response.content),
            body=body_text,
            body_format=body_format,
            raw_detail=text_preview(flow.response.content[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
        )

    def _ensure_key(self, ctx: MitmContext) -> None:
        if ctx.weapi_private_key is not None and ctx.weapi_modulus_hex:
            return
        key_path = getattr(ctx, "weapi_private_key_file", DEFAULT_WEAPI_PRIVATE_KEY_FILE)
        private_key = load_or_create_weapi_private_key(key_path)
        numbers = private_key.private_numbers().public_numbers
        ctx.weapi_private_key = private_key
        ctx.weapi_exponent_hex = _rsa_component_hex(numbers.e)
        ctx.weapi_modulus_hex = _rsa_component_hex(numbers.n)

    def _decrypt_request_payload(self, ctx: MitmContext, params: str, enc_sec_key: str) -> tuple[bytes, bytes]:
        rsa_plain = self._decrypt_enc_sec_key(ctx, enc_sec_key)
        candidates = [rsa_plain]
        reversed_plain = rsa_plain[::-1]
        if reversed_plain != rsa_plain:
            candidates.append(reversed_plain)
        errors: list[str] = []
        for candidate in candidates:
            try:
                return candidate, decrypt_weapi_params(params, candidate)
            except Exception as exc:
                errors.append(str(exc))
        raise ValueError("AES decrypt failed for RSA plaintext candidates: " + "; ".join(errors))

    def _decrypt_enc_sec_key(self, ctx: MitmContext, enc_sec_key: str) -> bytes:
        private_key = ctx.weapi_private_key
        if private_key is None:
            raise ValueError("weapi private key missing")
        cipher = bytes.fromhex(enc_sec_key)
        key_size = private_key.key_size // 8
        if len(cipher) > key_size:
            raise ValueError(f"encSecKey too long for RSA key: {len(cipher)} > {key_size}")
        decrypted = pow(int.from_bytes(cipher, "big"), private_key.private_numbers().d, private_key.private_numbers().public_numbers.n)
        raw = decrypted.to_bytes(key_size, "big").lstrip(b"\x00")
        if not raw:
            raise ValueError("empty RSA plaintext")
        return raw


def load_or_create_weapi_private_key(path: Path) -> rsa.RSAPrivateKey:
    if path.exists():
        key = load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"weapi key must be an RSA private key: {path}")
        return key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        private_key.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )
    )
    return private_key


def decrypt_weapi_params(params: str, aes_key: bytes) -> bytes:
    inner_b64 = _aes_cbc_decrypt(base64.b64decode(params), aes_key)
    return _aes_cbc_decrypt(base64.b64decode(inner_b64), WEAPI_PRESET_KEY)


def encrypt_weapi_params(plain: bytes, aes_key: bytes) -> str:
    inner = base64.b64encode(_aes_cbc_encrypt(plain, WEAPI_PRESET_KEY))
    return base64.b64encode(_aes_cbc_encrypt(inner, aes_key)).decode("ascii")


def rsa_encrypt_no_padding_hex(plain: bytes, exponent_hex: str, modulus_hex: str) -> str:
    modulus = int(modulus_hex, 16)
    exponent = int(exponent_hex, 16)
    key_size = (modulus.bit_length() + 7) // 8
    if len(plain) > key_size:
        raise ValueError(f"RSA plaintext too long: {len(plain)} > {key_size}")
    encrypted = pow(int.from_bytes(plain, "big"), exponent, modulus)
    return encrypted.to_bytes(key_size, "big").hex()


def _aes_cbc_decrypt(raw: bytes, aes_key: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(WEAPI_IV)).decryptor()
    padded = decryptor.update(raw) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _aes_cbc_encrypt(plain: bytes, aes_key: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(WEAPI_IV)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _first(values: dict[str, list[str]], key: str) -> str:
    items = values.get(key)
    return items[0] if items else ""


def _payload_text(plain: bytes) -> tuple[str, str]:
    text = plain.decode("utf-8", errors="replace")
    try:
        parsed: Any = json.loads(text)
    except Exception:
        return text, "text"
    return json.dumps(parsed, ensure_ascii=False, indent=2), "json"


def _is_core_js_url(url: str) -> bool:
    return CORE_JS_RE.match(url) is not None


def _rsa_component_hex(value: int) -> str:
    text = f"{value:x}"
    if len(text) % 2:
        text = "0" + text
    if text[:2].lower() not in {"00"} and int(text[:2], 16) >= 0x80:
        text = "00" + text
    return text
