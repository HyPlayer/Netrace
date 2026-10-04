#!/usr/bin/env python3
from __future__ import annotations

from mitmproxy import http
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from aegis_xeapi import b64e
from tool.aegis_mitm_core import (
    decode_key_response_body,
    encode_key_response_body,
    rewrite_key_response,
)
from tool.mitm_context import MitmContext


def rewrite_aegis_key_response(
    flow: http.HTTPFlow,
    ctx: MitmContext,
    *,
    protocol: str,
    static_key: bytes | None = None,
    sign_key: bytes | None = None,
) -> bool:
    if flow.response is None:
        return False
    body = decode_key_response_body(flow.response.content)
    result = rewrite_key_response(
        body.payload,
        proxy_public_key_b64=b64e(ctx.proxy_public),
        static_key=static_key or ctx.static_key,
        sign_key=sign_key or ctx.sign_key,
        request_nonce=flow.metadata.get("aegis_request_nonce"),
        ttl_seconds=ctx.public_key_ttl_seconds,
    )
    if result is None:
        return False
    ctx.real_public_info = result.public_info
    ctx.refresh_requested = False
    flow.metadata["aegis_mitm_hit"] = True
    flow.response.content = encode_key_response_body(
        result.payload,
        body.encoding,
        legacy_gzip=body.legacy_gzip,
    )
    flow.response.headers["content-length"] = str(len(flow.response.content))
    ctx.emit_event(
        "key-response",
        flow,
        protocol=protocol,
        operation="key-response",
        key_flow=True,
        status="forged encrypted" if result.encrypted_response else "forged plain",
        version=result.public_info.version,
        sk=result.public_info.sk,
        signature_ok=result.signature_ok,
        body_encoding=body.encoding,
        body_gzip=body.legacy_gzip,
        plaintext_encoding=result.plaintext_encoding,
        public_key_ttl_seconds=ctx.public_key_ttl_seconds,
        proxy_public_key=b64e(ctx.proxy_public),
        proxy_private_key=b64e(
            ctx.proxy_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        ),
    )
    return True
