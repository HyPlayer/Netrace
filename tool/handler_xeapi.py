#!/usr/bin/env python3
from __future__ import annotations

from mitmproxy import http

from aegis_xeapi import decode_session_key
from tool.aegis_mitm_core import (
    key_material,
    key_profile_from_os,
    is_key_api_path,
    decrypt_and_rewrap_xeapi_request,
    decrypt_eapi_request_body,
    extract_request_nonce,
    text_preview,
    try_decrypt_response_body,
)
from tool.key_hijack import rewrite_aegis_key_response
from tool.mitm_context import MitmContext
from tool.protocols import BaseProtocolHandler


class XeapiHandler(BaseProtocolHandler):
    name = "xeapi"

    def matches_request(self, flow: http.HTTPFlow) -> bool:
        # Normal xeapi traffic is handled here.  The direct BSR endpoint is
        # also owned by this handler so its JSON request/response can use the
        # same key replacement logic as the legacy eapi endpoint.
        return "/xeapi/" in flow.request.path or (
            flow.request.path.startswith("/api/") and is_key_api_path(flow.request.path)
        )

    def is_key_flow(self, flow: http.HTTPFlow, ctx: MitmContext) -> bool:
        if is_key_api_path(flow.request.path):
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
        return is_key_api_path(body.api_path)

    def handle_key_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        profile = self._key_profile(flow)
        flow.metadata["aegis_key_profile"] = profile
        nonce = extract_request_nonce(flow.request.content)
        flow.metadata["netrace_protocol"] = self.name
        flow.metadata["netrace_key_handler"] = self.name
        if nonce:
            flow.metadata["aegis_request_nonce"] = nonce
            ctx.emit_event(
                "key-request",
                flow,
                protocol=self.name,
                operation="key-request",
                key_flow=True,
                status=f"nonce={nonce}",
            )

    def handle_key_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        if flow.response is None:
            return
        try:
            profile = flow.metadata.get("aegis_key_profile", "mobile")
            static_key, sign_key = key_material(profile)
            rewrite_aegis_key_response(
                flow, ctx, protocol=self.name, static_key=static_key, sign_key=sign_key
            )
        except Exception as exc:
            dump_path = ctx.dump(flow, "key-response-failed", flow.response.content)
            ctx.emit_event(
                "key-response-failed",
                flow,
                protocol=self.name,
                operation="key-response",
                key_flow=True,
                status=str(exc),
                detail=text_preview(flow.response.content[:1000]),
                first32=flow.response.content[:32].hex(),
                dump_path=str(dump_path) if dump_path else None,
            )

    def handle_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        # Some PC clients route legacy eapi envelopes through a xeapi-looking
        # URL.  Do not feed their `params` body to the B/S/R decoder.
        if "/eapi/" in flow.request.path:
            try:
                values = urllib.parse.parse_qs(flow.request.content.decode("utf-8"), keep_blank_values=True)
            except Exception:
                values = {}
            if "params" in values and not {"B", "S", "R"}.issubset(values):
                try:
                    body = decrypt_eapi_request_body(flow.request.content)
                    flow.metadata["aegis_mitm_hit"] = True
                    flow.metadata["aegis_protocol"] = "eapi"
                    flow.metadata["netrace_protocol"] = "eapi"
                    ctx.emit_event(
                        "request",
                        flow,
                        protocol="eapi",
                        operation="request",
                        status="eapi-decrypted",
                        detail=text_preview(body.plain),
                        eapi_path=body.api_path,
                        eapi_digest=body.digest,
                        eapi_digest_ok=body.digest_ok,
                    )
                    return
                except Exception:
                    pass
        if ctx.real_public_info is None:
            ctx.emit_event(
                "miss",
                flow,
                protocol=self.name,
                operation="miss",
                status="real public key missing; wait for key/get",
            )
            return
        content_type = flow.request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            ctx.emit_event(
                "miss",
                flow,
                protocol=self.name,
                operation="miss",
                status=f"unexpected content-type: {content_type or '<empty>'}",
            )
            return
        raw_request = flow.request.content
        try:
            static_key, _ = key_material(self._key_profile(flow))
            rewritten, dynamic_key, plain, r_plain = decrypt_and_rewrap_xeapi_request(
                raw_request,
                static_key=static_key,
                proxy_private_key=ctx.proxy_private,
                real_public_info=ctx.real_public_info,
                hkdf_salt=ctx.hkdf_salt,
                hkdf_info=ctx.hkdf_info,
            )
        except Exception as exc:
            try:
                form_values = urllib.parse.parse_qs(raw_request.decode("utf-8"), keep_blank_values=True)
                wire_diag = {
                    "form_fields": sorted(form_values),
                    "C_len": len(form_values.get("C", [""])[0]),
                    "B_len": len(form_values.get("B", [""])[0]),
                    "S_len": len(form_values.get("S", [""])[0]),
                    "R_len": len(form_values.get("R", [""])[0]),
                }
            except Exception:
                wire_diag = {}
            ctx.emit_event(
                "decrypt-failed",
                flow,
                protocol=self.name,
                operation="decrypt-failed",
                status=str(exc),
                key_profile=self._key_profile(flow),
                **wire_diag,
                request_dump_path=str(ctx.dump(flow, "csr-request-failed", raw_request) or "") or None,
            )
            return
        flow.request.content = rewritten
        flow.request.headers["content-length"] = str(len(rewritten))
        flow.metadata["aegis_mitm_hit"] = True
        flow.metadata["aegis_protocol"] = self.name
        flow.metadata["netrace_protocol"] = self.name
        ctx.request_keys[flow.id] = dynamic_key
        raw_dump_path = ctx.dump(flow, "request-raw", raw_request)
        dump_path = ctx.dump(flow, "request", plain)
        body_text, body_format = ctx.extract_body_payload_text(plain)
        ctx.emit_event(
            "request",
            flow,
            protocol=self.name,
            operation="request",
            status="decrypted",
            detail=text_preview(plain),
            body=body_text,
            body_format=body_format,
            raw_detail=text_preview(raw_request[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
            r_plain=text_preview(r_plain, 500),
            dump_path=str(dump_path) if dump_path else None,
        )

    def handle_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        if flow.response is None:
            return
        if not flow.metadata.get("aegis_mitm_hit"):
            self._maybe_force_key_refresh(flow, ctx)
            return
        ud_sts = flow.response.headers.get("x-ud-sts")
        if ud_sts:
            ctx.emit_event(
                "status",
                flow,
                protocol=self.name,
                operation="response",
                status=f"x-ud-sts={ud_sts}",
            )
        ssid = flow.response.headers.get("x-encr-ssid")
        sskey = flow.response.headers.get("x-encr-sskey")
        if ssid and sskey:
            ctx.session_id = ssid
            ctx.session_key = decode_session_key(sskey)
            ctx.session_keys[ssid] = ctx.session_key
            ctx.emit_event(
                "session",
                flow,
                protocol=self.name,
                operation="session",
                status="updated",
                session_id=ssid,
                session_key=sskey,
            )

        session_key = ctx.session_keys.get(ssid or "") or ctx.session_key
        result = try_decrypt_response_body(
            flow.response.content,
            request_key=ctx.request_keys.get(flow.id),
            session_key=session_key,
            mode=ctx.response_mode,
        )
        if result is None:
            dump_path = ctx.dump(flow, "response-decrypt-failed", flow.response.content)
            response_body_text, response_body_format = ctx.extract_body_payload_text(flow.response.content)
            ctx.emit_event(
                "response-decrypt-failed",
                flow,
                protocol=self.name,
                operation="response",
                status=f"mode={ctx.response_mode}",
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
        raw_dump_path = ctx.dump(flow, "response-raw", flow.response.content)
        dump_path = ctx.dump(flow, "response", plain)
        response_body_text, response_body_format = ctx.extract_body_payload_text(plain)
        ctx.emit_event(
            "response",
            flow,
            protocol=self.name,
            operation="response",
            status=f"decrypted:{mode}",
            detail=text_preview(plain),
            body=response_body_text,
            body_format=response_body_format,
            raw_detail=text_preview(flow.response.content[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
            dump_path=str(dump_path) if dump_path else None,
        )

    def _maybe_force_key_refresh(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        if flow.response is None:
            return
        if ctx.real_public_info is not None:
            return
        if not ctx.force_key_refresh_on_miss or ctx.refresh_requested:
            return
        ctx.refresh_requested = True
        flow.response.headers["x-ud-sts"] = "10000"
        ctx.emit_event(
            "force-key-refresh",
            flow,
            protocol=self.name,
            operation="key-request",
            status="injected x-ud-sts=10000",
        )

    def _key_profile(self, flow: http.HTTPFlow) -> str:
        header_os = flow.request.headers.get("x-os") or flow.request.headers.get("X-OS")
        if header_os:
            return key_profile_from_os(header_os)
        content_type = flow.request.headers.get("content-type", "").lower()
        if "json" in content_type or flow.request.content.lstrip().startswith(b"{"):
            try:
                import json
                payload = json.loads(flow.request.content.decode("utf-8"))
                if isinstance(payload, dict):
                    return key_profile_from_os(payload.get("os"))
            except Exception:
                pass
        if "/eapi/" in flow.request.path:
            try:
                body = decrypt_eapi_request_body(flow.request.content)
                import json
                payload = json.loads(body.plain.decode("utf-8"))
                if isinstance(payload, dict):
                    return key_profile_from_os(payload.get("os"))
            except Exception:
                pass
        cookie = flow.request.headers.get("cookie", "")
        for item in cookie.split(";"):
            name, _, value = item.strip().partition("=")
            if name.lower() == "os" and value:
                return key_profile_from_os(value)
        return "mobile"
