#!/usr/bin/env python3
"""
mitmproxy addon for Aegis /xeapi traffic.

It performs an active public-key substitution so the proxy can unwrap S:

1. The real key/get response is saved.
2. The response publicKey is replaced with this proxy's X25519 public key.
3. Later /xeapi requests are decrypted locally, then S is rewrapped with the
   real server public key before forwarding.

Run:

    mitmproxy -s mitm_aegis_xeapi.py --set aegis_static_key=hex:001122...

Optional:

    --set aegis_dump_dir=E:\\HyPlayer\\XeApi\\mitm_dumps
    --set aegis_hkdf_salt=b64:...
    --set aegis_hkdf_info=raw-info
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric import x25519
from mitmproxy import ctx, http

from aegis_xeapi import AegisCrypto, PublicKeyInfo, b64d, b64e, decode_key


KEY_PATH_MARKER = "/gorilla/anti/crawler/security/key/get"


def _decode_option_bytes(value: str) -> bytes | None:
    if not value:
        return None
    return decode_key(value)


def _json_loads_bytes(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"))


def _json_dumps_bytes(data: Any) -> bytes:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _extract_key_payload(payload: Any) -> Mapping[str, Any] | None:
    if isinstance(payload, Mapping):
        data = payload.get("data")
        if isinstance(data, Mapping):
            return data
        return payload
    return None


def _replace_key_payload(payload: Any, proxy_public_key_b64: str) -> bool:
    data = _extract_key_payload(payload)
    if data is None or not data.get("publicKey"):
        return False
    data["publicKey"] = proxy_public_key_b64
    return True


def _content_as_text(flow: http.HTTPFlow) -> str:
    if flow.response is None:
        return ""
    try:
        return flow.response.get_text(strict=False)
    except ValueError:
        return flow.response.content.decode("utf-8", errors="replace")


class AegisMitm:
    def __init__(self) -> None:
        self.static_key = b""
        self.hkdf_salt = b""
        self.hkdf_info: bytes | None = None
        self.dump_dir: Path | None = None
        self.proxy_private = x25519.X25519PrivateKey.generate()
        self.proxy_public = self.proxy_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.real_public_info: PublicKeyInfo | None = None
        self.request_keys: dict[str, bytes] = {}
        self.session_key: bytes | None = None

    def load(self, loader) -> None:  # type: ignore[no-untyped-def]
        loader.add_option("aegis_static_key", str, "", "Aegis static AES key, e.g. hex:001122...")
        loader.add_option("aegis_hkdf_salt", str, "", "HKDF salt for S wrapping, e.g. b64:...")
        loader.add_option("aegis_hkdf_info", str, "", "HKDF info for S wrapping, e.g. raw text or hex:...")
        loader.add_option("aegis_dump_dir", str, "", "Directory for decrypted request/response dumps.")

    def configure(self, updated: set[str]) -> None:
        if "aegis_static_key" in updated or not self.static_key:
            if ctx.options.aegis_static_key:
                self.static_key = decode_key(ctx.options.aegis_static_key)
        if "aegis_hkdf_salt" in updated:
            self.hkdf_salt = _decode_option_bytes(ctx.options.aegis_hkdf_salt) or b""
        if "aegis_hkdf_info" in updated:
            self.hkdf_info = _decode_option_bytes(ctx.options.aegis_hkdf_info)
        if "aegis_dump_dir" in updated:
            self.dump_dir = Path(ctx.options.aegis_dump_dir) if ctx.options.aegis_dump_dir else None
            if self.dump_dir:
                self.dump_dir.mkdir(parents=True, exist_ok=True)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        if KEY_PATH_MARKER in flow.request.path:
            self._handle_key_response(flow)
            return
        if "/xeapi/" in flow.request.path:
            self._handle_xeapi_response(flow)

    def request(self, flow: http.HTTPFlow) -> None:
        if "/xeapi/" not in flow.request.path:
            return
        if not self.static_key:
            ctx.log.warn("aegis_static_key is missing; cannot decrypt /xeapi request")
            return
        if self.real_public_info is None:
            ctx.log.warn("real public key is missing; wait for key/get or provide a captured flow first")
            return
        content_type = flow.request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            return
        try:
            rewritten, dynamic_key, plain = self._decrypt_and_rewrite_request(flow.request.content)
        except Exception as exc:
            ctx.log.warn(f"Aegis request decrypt failed: {exc}")
            return

        flow.request.content = rewritten
        self.request_keys[flow.id] = dynamic_key
        ctx.log.info(f"Aegis request plain {flow.request.method} {flow.request.pretty_url}: {plain!r}")
        self._dump(flow, "request", plain)

    def _handle_key_response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        try:
            payload = _json_loads_bytes(flow.response.content)
            real_data = _extract_key_payload(payload)
            if real_data is None:
                return
            self.real_public_info = PublicKeyInfo.from_json(real_data)
            proxy_key_b64 = b64e(self.proxy_public)
            if not _replace_key_payload(payload, proxy_key_b64):
                return
            flow.response.content = _json_dumps_bytes(payload)
            flow.response.headers["content-length"] = str(len(flow.response.content))
            ctx.log.info(
                "Aegis key/get publicKey replaced; "
                f"version={self.real_public_info.version!r} sk_len={len(self.real_public_info.sk)}"
            )
        except Exception as exc:
            ctx.log.warn(f"Aegis key/get rewrite failed: {exc}")

    def _decrypt_and_rewrite_request(self, body: bytes) -> tuple[bytes, bytes, bytes]:
        values = urllib.parse.parse_qs(body.decode("utf-8"), keep_blank_values=True)
        for required in ("B", "S", "R"):
            if required not in values:
                raise ValueError(f"missing form field {required}")

        s_plain = AegisCrypto.unwrap_dynamic_key_for_test(
            b64d(values["S"][0]),
            own_private_key=self.proxy_private,
            salt=self.hkdf_salt,
            info=self.hkdf_info,
        )
        dynamic_key = self._dynamic_key_from_s_plain(s_plain)
        plain = AegisCrypto.decrypt_business_data(
            b64d(values["B"][0]),
            static_key=self.static_key,
            dynamic_key=dynamic_key,
        )

        real_s = AegisCrypto.wrap_dynamic_key(
            s_plain,
            peer_public_key=self.real_public_info.public_key,  # type: ignore[union-attr]
            salt=self.hkdf_salt,
            info=self.hkdf_info,
        )
        values["S"] = [b64e(real_s)]
        rewritten = urllib.parse.urlencode({k: v[0] for k, v in values.items()}).encode("utf-8")
        return rewritten, dynamic_key, plain

    def _handle_xeapi_response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        sskey = flow.response.headers.get("x-encr-sskey")
        if sskey:
            self.session_key = self._normalize_aes_key(sskey.encode("utf-8"))
            ctx.log.info("Aegis session key updated from x-encr-sskey")

        key = self.session_key or self.request_keys.get(flow.id)
        if not key:
            return
        text = _content_as_text(flow).strip()
        if not text:
            return
        try:
            plain = AegisCrypto.aes_decrypt(key, b64d(text), mode=1)
            ctx.log.info(f"Aegis response plain {flow.request.pretty_url}: {plain!r}")
            self._dump(flow, "response", plain)
        except Exception as exc:
            ctx.log.warn(f"Aegis response decrypt failed: {exc}")

    def _dump(self, flow: http.HTTPFlow, kind: str, plain: bytes) -> None:
        if self.dump_dir is None:
            return
        digest = hashlib.sha1(flow.request.pretty_url.encode("utf-8")).hexdigest()[:10]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = self.dump_dir / f"{stamp}-{kind}-{digest}.txt"
        path.write_bytes(plain)

    @staticmethod
    def _dynamic_key_from_s_plain(s_plain: bytes) -> bytes:
        if len(s_plain) < 24:
            raise ValueError("S plaintext is too short to contain base64(dynamicKey)")
        dynamic_key = base64.b64decode(s_plain[:24])
        if len(dynamic_key) not in (16, 24, 32):
            raise ValueError(f"unexpected dynamic key length: {len(dynamic_key)}")
        return dynamic_key

    @staticmethod
    def _normalize_aes_key(key: bytes) -> bytes:
        if len(key) in (16, 24, 32):
            return key
        return hashlib.sha256(key).digest()[:16]


addons = [AegisMitm()]
