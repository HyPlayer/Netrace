#!/usr/bin/env python3
from __future__ import annotations

from mitmproxy import http

from tool.aegis_mitm_core import (
    decrypt_eapi_request_body,
    text_preview,
    try_decrypt_response_body,
)
from tool.mitm_context import MitmContext
from tool.protocols import BaseProtocolHandler


class EapiHandler(BaseProtocolHandler):
    name = "eapi"

    def matches_request(self, flow: http.HTTPFlow) -> bool:
        return "/eapi/" in flow.request.path

    def handle_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        content_type = flow.request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" not in content_type:
            ctx.emit_event(
                "miss",
                flow,
                protocol=self.name,
                operation="miss",
                status=f"unexpected eapi content-type: {content_type or '<empty>'}",
            )
            return
        raw_request = flow.request.content
        try:
            body = decrypt_eapi_request_body(raw_request)
        except Exception as exc:
            ctx.emit_event(
                "decrypt-failed",
                flow,
                protocol=self.name,
                operation="decrypt-failed",
                status=f"eapi: {exc}",
            )
            return

        flow.metadata["aegis_mitm_hit"] = True
        flow.metadata["aegis_protocol"] = self.name
        flow.metadata["netrace_protocol"] = self.name
        raw_dump_path = ctx.dump(flow, "eapi-request-raw", raw_request)
        dump_path = ctx.dump(flow, "eapi-request", body.plain)
        body_text, body_format = ctx.extract_body_payload_text(body.plain)
        ctx.emit_event(
            "request",
            flow,
            protocol=self.name,
            operation="request",
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

    def handle_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        if flow.response is None or not flow.metadata.get("aegis_mitm_hit"):
            return
        result = try_decrypt_response_body(
            flow.response.content,
            request_key=None,
            session_key=None,
            mode="legacy",
        )
        if result is None:
            dump_path = ctx.dump(flow, "eapi-response-decrypt-failed", flow.response.content)
            response_body_text, response_body_format = ctx.extract_body_payload_text(flow.response.content)
            ctx.emit_event(
                "response-decrypt-failed",
                flow,
                protocol=self.name,
                operation="response",
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
        raw_dump_path = ctx.dump(flow, "eapi-response-raw", flow.response.content)
        dump_path = ctx.dump(flow, "eapi-response", plain)
        response_body_text, response_body_format = ctx.extract_body_payload_text(plain)
        ctx.emit_event(
            "response",
            flow,
            protocol=self.name,
            operation="response",
            status=f"eapi-decrypted:{mode}",
            detail=text_preview(plain),
            body=response_body_text,
            body_format=response_body_format,
            raw_detail=text_preview(flow.response.content[:2000]),
            raw_dump_path=str(raw_dump_path) if raw_dump_path else None,
            dump_path=str(dump_path) if dump_path else None,
        )
