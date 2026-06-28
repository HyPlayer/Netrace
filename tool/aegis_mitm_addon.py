#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mitmproxy import ctx, http

from aegis_xeapi import decode_key
from tool.aegis_mitm_core import DEFAULT_SIGN_KEY_B64, DEFAULT_STATIC_KEY_HEX
from tool.handler_eapi import EapiHandler
from tool.handler_weapi import WeapiHandler
from tool.handler_xeapi import XeapiHandler
from tool.mitm_context import (
    DEFAULT_PROXY_PRIVATE_KEY_FILE,
    MitmContext,
    decode_proxy_private_key_bytes,
    extract_body_payload_text,
    load_or_create_proxy_private_key,
    public_bytes_for_private_key,
)
from tool.protocols import NETRACE_KEY_HANDLER, NETRACE_PROTOCOL, ProtocolRegistry


class AegisMitmAddon:
    def __init__(self) -> None:
        self.ctx = MitmContext()
        self.ctx.static_key = bytes.fromhex(DEFAULT_STATIC_KEY_HEX)
        self.ctx.sign_key = DEFAULT_SIGN_KEY_B64.encode("utf-8")
        self.registry = ProtocolRegistry([XeapiHandler(), EapiHandler(), WeapiHandler()])

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
        loader.add_option("weapi_private_key_file", str, "", "Persistent RSA private key file for /weapi MITM.")

    def configure(self, updated: set[str]) -> None:
        self.ctx.static_key = decode_key(ctx.options.aegis_static_key)
        self.ctx.sign_key = decode_key(ctx.options.aegis_sign_key)
        self.ctx.hkdf_salt = decode_key(ctx.options.aegis_hkdf_salt) if ctx.options.aegis_hkdf_salt else b""
        self.ctx.hkdf_info = decode_key(ctx.options.aegis_hkdf_info) if ctx.options.aegis_hkdf_info else None
        self.ctx.response_mode = ctx.options.aegis_response_mode
        self.ctx.force_key_refresh_on_miss = bool(ctx.options.aegis_force_key_refresh_on_miss)
        self.ctx.public_key_ttl_seconds = int(ctx.options.aegis_public_key_ttl_seconds)
        self.ctx.dump_dir = Path(ctx.options.aegis_dump_dir) if ctx.options.aegis_dump_dir else None
        self.ctx.event_log = Path(ctx.options.aegis_event_log) if ctx.options.aegis_event_log else None
        proxy_private_key_file = (
            Path(ctx.options.aegis_proxy_private_key_file)
            if ctx.options.aegis_proxy_private_key_file
            else DEFAULT_PROXY_PRIVATE_KEY_FILE
        )
        self.ctx.set_proxy_private_key_file(proxy_private_key_file)
        self.ctx.weapi_private_key_file = (
            Path(ctx.options.weapi_private_key_file)
            if ctx.options.weapi_private_key_file
            else self.ctx.weapi_private_key_file
        )
        if self.ctx.dump_dir:
            self.ctx.dump_dir.mkdir(parents=True, exist_ok=True)

    def request(self, flow: http.HTTPFlow) -> None:
        key_handler = self.registry.key_handler_for(flow, self.ctx)
        if key_handler is not None:
            flow.metadata[NETRACE_KEY_HANDLER] = key_handler.name
            flow.metadata[NETRACE_PROTOCOL] = key_handler.name
            key_handler.handle_key_request(flow, self.ctx)
            return

        handler = self.registry.request_handler_for(flow)
        if handler is None:
            return
        flow.metadata[NETRACE_PROTOCOL] = handler.name
        handler.handle_request(flow, self.ctx)

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return

        key_handler = self.registry.get(flow.metadata.get(NETRACE_KEY_HANDLER))
        if key_handler is None:
            key_handler = self.registry.key_handler_for(flow, self.ctx)
        if key_handler is not None:
            key_handler.handle_key_response(flow, self.ctx)
            return

        handler = self.registry.get(flow.metadata.get(NETRACE_PROTOCOL))
        if handler is None:
            handler = self.registry.request_handler_for(flow)
        if handler is None:
            return
        handler.handle_response(flow, self.ctx)


addons = [AegisMitmAddon()]
