#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from mitmproxy import ctx, http

from aegis_xeapi import b64d, b64e
from tool.aegis_mitm_core import text_preview, write_event


DEFAULT_PROXY_PRIVATE_KEY_FILE = Path(__file__).resolve().parent / "proxy-server-x25519.key"


def public_bytes_for_private_key(private_key: x25519.X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def load_or_create_proxy_private_key(path: Path) -> x25519.X25519PrivateKey:
    if path.exists():
        raw = decode_proxy_private_key_bytes(path.read_text(encoding="utf-8").strip())
        return x25519.X25519PrivateKey.from_private_bytes(raw)

    private_key = x25519.X25519PrivateKey.generate()
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(b64e(raw), encoding="utf-8")
    return private_key


def decode_proxy_private_key_bytes(value: str) -> bytes:
    if value.startswith("hex:"):
        raw = bytes.fromhex(value[4:])
    elif value.startswith("b64:"):
        raw = b64d(value[4:])
    else:
        raw = b64d(value)
    if len(raw) != 32:
        raise ValueError(f"X25519 private key must be 32 bytes, got {len(raw)}")
    return raw


def extract_body_payload_text(plain: bytes) -> tuple[str, str]:
    text = text_preview(plain, 1000000)
    try:
        payload = json.loads(text)
    except Exception:
        return text, "text"
    if isinstance(payload, dict) and isinstance(payload.get("body"), str):
        body_text = payload["body"]
        try:
            decoded = base64.b64decode(body_text)
        except Exception:
            return body_text, "body-text"
        return decoded.decode("utf-8", errors="replace"), "body:b64"
    return text, "json"


class MitmContext:
    def __init__(self) -> None:
        self.static_key: bytes = b""
        self.sign_key: bytes = b""
        self.hkdf_salt = b""
        self.hkdf_info: bytes | None = None
        self.response_mode = "auto"
        self.force_key_refresh_on_miss = True
        self.public_key_ttl_seconds = 600
        self.dump_dir: Path | None = None
        self.event_log: Path | None = None
        self.proxy_private_key_file = DEFAULT_PROXY_PRIVATE_KEY_FILE
        self.proxy_private = load_or_create_proxy_private_key(self.proxy_private_key_file)
        self.proxy_public = public_bytes_for_private_key(self.proxy_private)
        self.weapi_private_key_file = Path(__file__).resolve().parent / "weapi-rsa-private.key"
        self.weapi_private_key = None
        self.weapi_exponent_hex = "010001"
        self.weapi_modulus_hex = ""
        self.real_public_info = None
        self.request_keys: dict[str, bytes] = {}
        self.session_keys: dict[str, bytes] = {}
        self.session_id: str | None = None
        self.session_key: bytes | None = None
        self.refresh_requested = False

    def set_proxy_private_key_file(self, path: Path) -> None:
        if path == self.proxy_private_key_file:
            return
        self.proxy_private_key_file = path
        self.proxy_private = load_or_create_proxy_private_key(path)
        self.proxy_public = public_bytes_for_private_key(self.proxy_private)

    def dump(self, flow: http.HTTPFlow, kind: str, data: bytes) -> Path | None:
        if self.dump_dir is None:
            return None
        digest = hashlib.sha1(flow.request.pretty_url.encode("utf-8")).hexdigest()[:10]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = self.dump_dir / f"{stamp}-{kind}-{digest}.txt"
        path.write_bytes(data)
        return path

    def emit_event(
        self,
        kind: str,
        flow: http.HTTPFlow,
        *,
        protocol: str | None = None,
        operation: str | None = None,
        key_flow: bool | None = None,
        **extra: Any,
    ) -> None:
        event: dict[str, Any] = {
            "kind": kind,
            "flow_id": flow.id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "path": flow.request.path,
            "request_headers": dict(flow.request.headers),
        }
        if protocol is not None:
            event["protocol"] = protocol
        if operation is not None:
            event["operation"] = operation
        if key_flow is not None:
            event["key_flow"] = key_flow
        if flow.response is not None:
            event.update(
                {
                    "http_status": flow.response.status_code,
                    "response_headers": dict(flow.response.headers),
                }
            )
        event.update(extra)
        write_event(self.event_log, event)

    def warn(self, flow: http.HTTPFlow, message: str, *, protocol: str | None = None) -> None:
        ctx.log.warn(f"Netrace: {message}")
        self.emit_event("warn", flow, protocol=protocol, operation="warn", status=message)

    @staticmethod
    def text_preview(data: bytes, limit: int = 4000) -> str:
        return text_preview(data, limit)

    @staticmethod
    def extract_body_payload_text(plain: bytes) -> tuple[str, str]:
        return extract_body_payload_text(plain)

    @staticmethod
    def json_block(value: Mapping[str, Any]) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
