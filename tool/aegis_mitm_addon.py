#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from mitmproxy import ctx, http

from aegis_xeapi import b64d, b64e, decode_key, decode_session_key
from tool.aegis_mitm_core import (
    DEFAULT_SIGN_KEY_B64,
    DEFAULT_STATIC_KEY_HEX,
    KEY_PATH_MARKER,
    decode_key_response_body,
    decrypt_and_rewrap_xeapi_request,
    decrypt_eapi_request_body,
    encode_key_response_body,
    extract_request_nonce,
    rewrite_key_response,
    text_preview,
    try_decrypt_response_body,
    write_event,
)


DEFAULT_PROXY_PRIVATE_KEY_FILE = Path(__file__).resolve().parent / "proxy-server-x25519.key"


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


class AegisMitmAddon:
    def __init__(self) -> None:
        self.static_key = bytes.fromhex(DEFAULT_STATIC_KEY_HEX)
        self.sign_key = DEFAULT_SIGN_KEY_B64.encode("utf-8")
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
        self.real_public_info = None
        self.request_keys: dict[str, bytes] = {}
        self.session_id: str | None = None
        self.session_key: bytes | None = None
        self.refresh_requested = False

    def load(self, loader) -> None:  # type: ignore[no-untyped-def]
        loader.add_option("aegis_static_key", str, "hex:" + DEFAULT_STATIC_KEY_HEX, "Aegis static AES key.")
        loader.add_option("aegis_sign_key", str, DEFAULT_SIGN_KEY_B64, "Aegis key-refresh sign key.")
        loader.add_option("aegis_hkdf_salt", str, "", "HKDF salt override. Empty means native default zero32.")
        loader.add_option("aegis_hkdf_info", str, "", "HKDF info override. Empty means native default ephemeral public key.")
        loader.add_option("aegis_response_mode", str, "auto", "Response decrypt mode: auto, legacy, session.")
        loader.add_option(
            "aegis_force_key_refresh_on_miss",
            bool,
            True,
            "Inject x-ud-sts=10000 once when /xeapi is seen before key/get.",
        )
        loader.add_option("aegis_public_key_ttl_seconds", int, 600, "TTL for rewritten public keys.")
        loader.add_option(
            "aegis_proxy_private_key_file",
            str,
            str(DEFAULT_PROXY_PRIVATE_KEY_FILE),
            "Persistent X25519 private key file used as the forged Aegis server key.",
        )
        loader.add_option("aegis_dump_dir", str, "", "Directory for decrypted dumps.")
        loader.add_option("aegis_event_log", str, "", "JSONL event log path for the Textual TUI.")

    def configure(self, updated: set[str]) -> None:
        self.static_key = decode_key(ctx.options.aegis_static_key)
        self.sign_key = decode_key(ctx.options.aegis_sign_key)
        self.hkdf_salt = decode_key(ctx.options.aegis_hkdf_salt) if ctx.options.aegis_hkdf_salt else b""
        self.hkdf_info = decode_key(ctx.options.aegis_hkdf_info) if ctx.options.aegis_hkdf_info else None
        self.response_mode = ctx.options.aegis_response_mode
        self.force_key_refresh_on_miss = bool(ctx.options.aegis_force_key_refresh_on_miss)
        self.public_key_ttl_seconds = int(ctx.options.aegis_public_key_ttl_seconds)
        self.dump_dir = Path(ctx.options.aegis_dump_dir) if ctx.options.aegis_dump_dir else None
        self.event_log = Path(ctx.options.aegis_event_log) if ctx.options.aegis_event_log else None
        proxy_private_key_file = (
            Path(ctx.options.aegis_proxy_private_key_file)
            if ctx.options.aegis_proxy_private_key_file
            else DEFAULT_PROXY_PRIVATE_KEY_FILE
        )
        if proxy_private_key_file != self.proxy_private_key_file:
            self.proxy_private_key_file = proxy_private_key_file
            self.proxy_private = load_or_create_proxy_private_key(proxy_private_key_file)
            self.proxy_public = public_bytes_for_private_key(self.proxy_private)
        if self.dump_dir:
            self.dump_dir.mkdir(parents=True, exist_ok=True)

    def request(self, flow: http.HTTPFlow) -> None:
        if self._is_key_get_flow(flow):
            nonce = extract_request_nonce(flow.request.content)
            if nonce:
                flow.metadata["aegis_request_nonce"] = nonce
                self._event("key-request", flow, status=f"nonce={nonce}")
            return
        if "/eapi/" in flow.request.path:
            self._handle_eapi_request(flow)
            return
        if "/xeapi/" not in flow.request.path:
            return
        if self.real_public_info is None:
            self._event("miss", flow, status="real public key missing; wait for key/get")
            return
        content_type = flow.request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            self._event("miss", flow, status=f"unexpected content-type: {content_type or '<empty>'}")
            return
        raw_request = flow.request.content
        try:
            rewritten, dynamic_key, plain, r_plain = decrypt_and_rewrap_xeapi_request(
                raw_request,
                static_key=self.static_key,
                proxy_private_key=self.proxy_private,
                real_public_info=self.real_public_info,
                hkdf_salt=self.hkdf_salt,
                hkdf_info=self.hkdf_info,
            )
        except Exception as exc:
            self._event("decrypt-failed", flow, status=str(exc))
            return
        flow.request.content = rewritten
        flow.request.headers["content-length"] = str(len(rewritten))
        flow.metadata["aegis_mitm_hit"] = True
        self.request_keys[flow.id] = dynamic_key
        raw_dump_path = self._dump(flow, "request-raw", raw_request)
        dump_path = self._dump(flow, "request", plain)
        self._event(
            "request",
            flow,
            status="decrypted",
            detail=text_preview(plain),
            body=extract_body_payload_text(plain)[0],
            body_format=extract_body_payload_text(plain)[1],
            raw_detail=text_preview(raw_request[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
            r_plain=text_preview(r_plain, 500),
            dump_path=str(dump_path) if dump_path else None,
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        if self._is_key_get_flow(flow):
            self._handle_key_response(flow)
            return
        if "/xeapi/" in flow.request.path:
            if not flow.metadata.get("aegis_mitm_hit"):
                self._maybe_force_key_refresh(flow)
                return
            self._handle_xeapi_response(flow)
        elif "/eapi/" in flow.request.path:
            if flow.metadata.get("aegis_mitm_hit"):
                self._handle_eapi_response(flow)

    def _handle_eapi_request(self, flow: http.HTTPFlow) -> None:
        content_type = flow.request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            self._event("miss", flow, status=f"unexpected eapi content-type: {content_type or '<empty>'}")
            return
        raw_request = flow.request.content
        try:
            body = decrypt_eapi_request_body(raw_request)
        except Exception as exc:
            self._event("decrypt-failed", flow, status=f"eapi: {exc}")
            return

        flow.metadata["aegis_mitm_hit"] = True
        flow.metadata["aegis_protocol"] = "eapi"
        raw_dump_path = self._dump(flow, "eapi-request-raw", raw_request)
        dump_path = self._dump(flow, "eapi-request", body.plain)
        body_text, body_format = extract_body_payload_text(body.plain)
        self._event(
            "request",
            flow,
            status="eapi-decrypted",
            detail=text_preview(body.plain),
            body=body_text,
            body_format=body_format,
            raw_detail=text_preview(raw_request[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
            eapi_path=body.api_path,
            eapi_digest=body.digest,
            eapi_digest_ok=body.digest_ok,
            dump_path=str(dump_path) if dump_path else None,
        )

    def _is_key_get_flow(self, flow: http.HTTPFlow) -> bool:
        if KEY_PATH_MARKER in flow.request.path:
            return True
        if "/eapi/" not in flow.request.path:
            return False
        content_type = flow.request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            return False
        try:
            body = decrypt_eapi_request_body(flow.request.content)
        except Exception:
            return False
        return KEY_PATH_MARKER in body.api_path

    def _handle_key_response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        try:
            body = decode_key_response_body(flow.response.content)
            result = rewrite_key_response(
                body.payload,
                proxy_public_key_b64=b64e(self.proxy_public),
                static_key=self.static_key,
                sign_key=self.sign_key,
                request_nonce=flow.metadata.get("aegis_request_nonce"),
                ttl_seconds=self.public_key_ttl_seconds,
            )
            if result is None:
                return
            self.real_public_info = result.public_info
            self.refresh_requested = False
            flow.metadata["aegis_mitm_hit"] = True
            flow.response.content = encode_key_response_body(
                result.payload,
                body.encoding,
                legacy_gzip=body.legacy_gzip,
            )
            flow.response.headers["content-length"] = str(len(flow.response.content))
            self._event(
                "key-response",
                flow,
                status="forged encrypted" if result.encrypted_response else "forged plain",
                version=result.public_info.version,
                sk=result.public_info.sk,
                signature_ok=result.signature_ok,
                body_encoding=body.encoding,
                body_gzip=body.legacy_gzip,
                plaintext_encoding=result.plaintext_encoding,
                public_key_ttl_seconds=self.public_key_ttl_seconds,
            )
        except Exception as exc:
            dump_path = self._dump(flow, "key-response-failed", flow.response.content)
            self._event(
                "key-response-failed",
                flow,
                status=str(exc),
                detail=text_preview(flow.response.content[:1000]),
                first32=flow.response.content[:32].hex(),
                dump_path=str(dump_path) if dump_path else None,
            )
            return

    def _maybe_force_key_refresh(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        if self.real_public_info is not None:
            return
        if not self.force_key_refresh_on_miss or self.refresh_requested:
            return
        self.refresh_requested = True
        flow.response.headers["x-ud-sts"] = "10000"
        self._event("force-key-refresh", flow, status="injected x-ud-sts=10000")

    def _handle_xeapi_response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        ud_sts = flow.response.headers.get("x-ud-sts")
        if ud_sts:
            self._event("status", flow, status=f"x-ud-sts={ud_sts}")
        ssid = flow.response.headers.get("x-encr-ssid")
        sskey = flow.response.headers.get("x-encr-sskey")
        if ssid and sskey:
            self.session_id = ssid
            self.session_key = decode_session_key(sskey)
            self._event("session", flow, status="updated", session_id=ssid, session_key=sskey)

        result = try_decrypt_response_body(
            flow.response.content,
            request_key=self.request_keys.get(flow.id),
            session_key=self.session_key,
            mode=self.response_mode,
        )
        if result is None:
            dump_path = self._dump(flow, "response-decrypt-failed", flow.response.content)
            response_body_text, response_body_format = extract_body_payload_text(flow.response.content)
            self._event(
                "response-decrypt-failed",
                flow,
                status=f"mode={self.response_mode}",
                content_type=flow.response.headers.get("content-type", ""),
                content_encoding=flow.response.headers.get("content-encoding", ""),
                body_len=len(flow.response.content),
                first32=flow.response.content[:32].hex(),
                detail=text_preview(flow.response.content[:1000]),
                body=response_body_text,
                body_format=response_body_format,
                dump_path=str(dump_path) if dump_path else None,
            )
            return
        plain, mode = result
        raw_dump_path = self._dump(flow, "response-raw", flow.response.content)
        dump_path = self._dump(flow, "response", plain)
        response_body_text, response_body_format = extract_body_payload_text(plain)
        self._event(
            "response",
            flow,
            status=f"decrypted:{mode}",
            detail=text_preview(plain),
            body=response_body_text,
            body_format=response_body_format,
            raw_detail=text_preview(flow.response.content[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
            dump_path=str(dump_path) if dump_path else None,
        )

    def _handle_eapi_response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        result = try_decrypt_response_body(
            flow.response.content,
            request_key=None,
            session_key=None,
            mode="legacy",
        )
        if result is None:
            dump_path = self._dump(flow, "eapi-response-decrypt-failed", flow.response.content)
            response_body_text, response_body_format = extract_body_payload_text(flow.response.content)
            self._event(
                "response-decrypt-failed",
                flow,
                status="eapi:legacy-failed",
                content_type=flow.response.headers.get("content-type", ""),
                content_encoding=flow.response.headers.get("content-encoding", ""),
                body_len=len(flow.response.content),
                first32=flow.response.content[:32].hex(),
                detail=text_preview(flow.response.content[:1000]),
                body=response_body_text,
                body_format=response_body_format,
                dump_path=str(dump_path) if dump_path else None,
            )
            return
        plain, mode = result
        raw_dump_path = self._dump(flow, "eapi-response-raw", flow.response.content)
        dump_path = self._dump(flow, "eapi-response", plain)
        response_body_text, response_body_format = extract_body_payload_text(plain)
        self._event(
            "response",
            flow,
            status=f"eapi-decrypted:{mode}",
            detail=text_preview(plain),
            body=response_body_text,
            body_format=response_body_format,
            raw_detail=text_preview(flow.response.content[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
            dump_path=str(dump_path) if dump_path else None,
        )

    def _content_as_text(self, flow: http.HTTPFlow) -> str:
        if flow.response is None:
            return ""
        try:
            return flow.response.get_text(strict=False)
        except ValueError:
            return flow.response.content.decode("utf-8", errors="replace")

    def _dump(self, flow: http.HTTPFlow, kind: str, data: bytes) -> Path | None:
        if self.dump_dir is None:
            return None
        digest = hashlib.sha1(flow.request.pretty_url.encode("utf-8")).hexdigest()[:10]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = self.dump_dir / f"{stamp}-{kind}-{digest}.txt"
        path.write_bytes(data)
        return path

    def _warn(self, flow: http.HTTPFlow, message: str) -> None:
        ctx.log.warn(f"Aegis: {message}")
        self._event("warn", flow, status=message)

    def _event(self, kind: str, flow: http.HTTPFlow, **extra) -> None:  # type: ignore[no-untyped-def]
        write_event(
            self.event_log,
            {
                "kind": kind,
                "flow_id": flow.id,
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "path": flow.request.path,
                "request_headers": dict(flow.request.headers),
                **(
                    {
                        "http_status": flow.response.status_code,
                        "response_headers": dict(flow.response.headers),
                    }
                    if flow.response is not None
                    else {}
                ),
                **extra,
            },
        )

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


addons = [AegisMitmAddon()]
