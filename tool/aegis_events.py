#!/usr/bin/env python3
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SESSION_FIELD_NAMES = (
    "protocol",
    "operation",
    "key_flow",
    "version",
    "sk",
    "signature_ok",
    "body_encoding",
    "body_gzip",
    "plaintext_encoding",
    "public_key_ttl_seconds",
    "eapi_path",
    "eapi_digest",
    "eapi_digest_ok",
    "debug",
)


LOG_FIELD_NAMES = (
    "version",
    "sk",
    "session_id",
    "session_key",
    "r_plain",
    "signature_ok",
    "body_encoding",
    "plaintext_encoding",
    "public_key_ttl_seconds",
    "protocol",
    "operation",
    "key_flow",
    "dump_path",
)


@dataclass
class FlowRecord:
    flow_id: str
    first_ts: float
    last_ts: float
    method: str = ""
    url: str = ""
    path: str = ""
    http_status: str = ""
    phase: str = ""
    request_status: str = ""
    response_status: str = ""
    protocol: str = ""
    operation: str = ""
    session_id: str = ""
    session_key: str = ""
    r_plain: str = ""
    request_event: dict[str, Any] | None = None
    response_event: dict[str, Any] | None = None
    key_event: dict[str, Any] | None = None
    session_event: dict[str, Any] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    def apply(self, event: dict[str, Any]) -> None:
        self.events.append(event)
        self.last_ts = float(event.get("ts", self.last_ts))
        self.method = str(event.get("method") or self.method)
        self.url = str(event.get("url") or self.url)
        self.path = str(event.get("path") or self.path or self.url)
        self.protocol = str(event.get("protocol") or self.protocol)
        self.operation = str(event.get("operation") or self.operation)
        if "http_status" in event:
            self.http_status = str(event["http_status"])

        kind = str(event.get("kind", ""))
        status = str(event.get("status", ""))
        self.phase = kind or self.phase

        if kind in {"request", "decrypt-failed", "miss", "key-request"}:
            self.request_event = event
            self.request_status = status
            self.r_plain = str(event.get("r_plain") or self.r_plain)
        elif kind in {"response", "response-decrypt-failed", "key-response-failed"}:
            self.response_event = event
            self.response_status = status
        elif kind == "key-response":
            self.key_event = event
            self.response_status = status
        elif kind == "session":
            self.session_event = event
            self.session_id = str(event.get("session_id") or self.session_id)
            self.session_key = str(event.get("session_key") or self.session_key)
        elif kind == "status":
            self.response_status = status

        if event.get("session_id"):
            self.session_id = str(event["session_id"])
        if event.get("session_key"):
            self.session_key = str(event["session_key"])

    @property
    def display_status(self) -> str:
        if self.response_status:
            return self.response_status
        if self.request_status:
            return self.request_status
        return self.phase

    @property
    def display_path(self) -> str:
        return self.path or self.url or self.flow_id

    @property
    def display_protocol(self) -> str:
        return self.protocol or "-"

    @property
    def search_text(self) -> str:
        chunks = [
            self.flow_id,
            self.method,
            self.url,
            self.path,
            self.http_status,
            self.phase,
            self.request_status,
            self.response_status,
            self.protocol,
            self.operation,
            self.session_id,
        ]
        for event in self.events:
            for name in ("kind", "status", "protocol", "operation", "detail", "body", "raw_detail"):
                value = event.get(name)
                if value is not None:
                    chunks.append(str(value))
        return "\n".join(chunks).lower()


class FlowStore:
    def __init__(self) -> None:
        self.flows: dict[str, FlowRecord] = {}
        self.order: list[str] = []

    def clear(self) -> None:
        self.flows.clear()
        self.order.clear()

    def apply(self, event: dict[str, Any]) -> tuple[FlowRecord, bool]:
        flow_id = str(event.get("flow_id") or f"event:{event.get('ts', time.time())}")
        flow = self.flows.get(flow_id)
        is_new = flow is None
        if flow is None:
            event_ts = float(event.get("ts", time.time()))
            flow = FlowRecord(flow_id=flow_id, first_ts=event_ts, last_ts=event_ts)
            self.flows[flow_id] = flow
            self.order.append(flow_id)
        flow.apply(event)
        return flow, is_new

    def get(self, flow_id: str | None) -> FlowRecord | None:
        if not flow_id:
            return None
        return self.flows.get(flow_id)

    def records(self) -> list[FlowRecord]:
        return [self.flows[flow_id] for flow_id in self.order if flow_id in self.flows]


class EventLogTailer:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = 0

    def reset(self) -> None:
        self.offset = 0

    def read_new(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as f:
            f.seek(self.offset)
            lines = f.readlines()
            self.offset = f.tell()
        events: list[dict[str, Any]] = []
        for line in lines:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events


def format_ts(value: float, *, include_date: bool = True) -> str:
    fmt = "%Y-%m-%d %H:%M:%S" if include_date else "%H:%M:%S"
    return time.strftime(fmt, time.localtime(value))


def json_block(value: Any, *, indent: int = 2) -> str:
    return json.dumps(value, ensure_ascii=False, indent=indent, default=str)


def compact_json_line(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def pretty_body_text(value: str) -> str:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return value
    return json_block(parsed)


def event_headers_text(event: dict[str, Any] | None, field: str) -> str:
    if event is None or field not in event:
        return ""
    return json_block(event[field])


def event_body_text(event: dict[str, Any] | None) -> str:
    if event is None:
        return ""
    value = event.get("body")
    if value is None:
        value = event.get("detail")
    return str(value) if value is not None else ""


def event_raw_text(event: dict[str, Any] | None) -> str:
    if event is None:
        return ""
    dump_path = event.get("raw_dump_path")
    if dump_path:
        try:
            return Path(str(dump_path)).read_bytes().decode("utf-8", errors="replace")
        except Exception:
            pass
    raw_detail = event.get("raw_detail")
    if raw_detail is not None:
        return str(raw_detail)
    detail = event.get("detail")
    return str(detail) if detail is not None else ""


def session_fields(flow: FlowRecord) -> dict[str, str]:
    fields: dict[str, str] = {
        "session_id": flow.session_id,
        "session_key": flow.session_key,
        "r_plain": flow.r_plain,
    }
    for event in flow.events:
        for name in SESSION_FIELD_NAMES:
            if name in event:
                fields[name] = str(event[name])
    return fields


def session_text(flow: FlowRecord) -> str:
    return json_block({name: value for name, value in session_fields(flow).items() if value})


def raw_events_text(flow: FlowRecord) -> str:
    return json_block(flow.events)


def copy_value_for_id(flow: FlowRecord | None, copy_id: str) -> str:
    if flow is None:
        return ""
    request_event = flow.request_event
    response_event = flow.response_event or flow.key_event

    if copy_id in {"url", "copy-overview-url", "copy-request-url", "copy-request-body-url", "copy-response-body-url"}:
        return flow.url
    if copy_id in {"request-headers", "copy-overview-request-headers", "copy-request-headers"}:
        return event_headers_text(request_event, "request_headers")
    if copy_id in {"response-headers", "copy-overview-response-headers", "copy-response-headers"}:
        return event_headers_text(response_event, "response_headers")
    if copy_id in {"request-body", "copy-overview-request-body", "copy-request-body", "copy-request-body-tab"}:
        return event_body_text(request_event)
    if copy_id in {"response-body", "copy-overview-response-body", "copy-response-body", "copy-response-body-tab"}:
        return event_body_text(response_event)
    if copy_id in {"request-raw", "copy-request-raw", "copy-raw-request"}:
        return event_raw_text(request_event)
    if copy_id in {"response-raw", "copy-response-raw", "copy-raw-response"}:
        return event_raw_text(response_event)
    if copy_id in {"raw-events", "copy-raw-events"}:
        return raw_events_text(flow)
    if copy_id in {"session-info", "copy-session-info"}:
        return session_text(flow)
    if copy_id in {"session-key", "copy-session-key"}:
        return flow.session_key
    if copy_id in {"session-r-plain", "copy-session-r-plain"}:
        return flow.r_plain
    return ""


def overview_text(flow: FlowRecord) -> str:
    fields = [
        ("Flow", flow.flow_id),
        ("Protocol", flow.display_protocol),
        ("Method", flow.method or "-"),
        ("URL", flow.url or "-"),
        ("HTTP", flow.http_status or "-"),
        ("State", flow.display_status or "-"),
        ("Events", str(len(flow.events))),
        ("First Seen", format_ts(flow.first_ts)),
        ("Updated", format_ts(flow.last_ts)),
    ]
    dump_paths = [str(event.get("dump_path")) for event in flow.events if event.get("dump_path")]
    if dump_paths:
        fields.append(("Dumps", "\n".join(dump_paths)))
    return "\n".join(f"{name}: {value}" for name, value in fields)


def event_detail_text(title: str, event: dict[str, Any] | None) -> str:
    if event is None:
        return f"{title}\n\nNo data for this tab yet."
    lines = [title, ""]
    for name in ("kind", "status", "protocol", "operation", "method", "url", "http_status", "content_type", "content_encoding", "body_len", "dump_path"):
        if name in event:
            lines.append(f"{name}: {event[name]}")
    if "request_headers" in event:
        lines.extend(["", "request headers:", json_block(event["request_headers"])])
    if "response_headers" in event:
        lines.extend(["", "response headers:", json_block(event["response_headers"])])
    if event.get("detail"):
        lines.extend(["", "body:", pretty_body_text(str(event["detail"]))])
    return "\n".join(lines)


def body_detail_text(title: str, event: dict[str, Any] | None) -> str:
    if event is None:
        return f"{title}\n\nNo payload yet."
    payload = event.get("body") or event.get("detail") or ""
    body_format = str(event.get("body_format") or "payload")
    return f"{title} ({body_format})\n\n{pretty_body_text(str(payload))}"


def raw_detail_text(flow: FlowRecord) -> str:
    lines = ["Raw Events / Bodies", ""]
    for label, event in (("request raw", flow.request_event), ("response raw", flow.response_event)):
        if event is None:
            continue
        if event.get("raw_dump_path"):
            lines.append(f"{label} dump: {event['raw_dump_path']}")
        if event.get("raw_detail"):
            lines.extend([f"{label} preview:", str(event["raw_detail"])])
    lines.extend(["events:", raw_events_text(flow)])
    return "\n".join(lines)


def session_detail_text(flow: FlowRecord) -> str:
    fields = session_fields(flow)
    return "\n".join(f"{name}: {value or '-'}" for name, value in fields.items())


def flow_events_jsonl(flows: Iterable[FlowRecord]) -> str:
    lines: list[str] = []
    for flow in flows:
        for event in flow.events:
            lines.append(compact_json_line(event))
    return "\n".join(lines) + ("\n" if lines else "")


def log_event_text(event: dict[str, Any]) -> str:
    ts = format_ts(float(event.get("ts", time.time())), include_date=False)
    kind = str(event.get("kind", ""))
    status = str(event.get("status", ""))
    path = str(event.get("path") or event.get("url") or "")
    lines = [f"{ts} {kind} {status}", path]
    for name in LOG_FIELD_NAMES:
        if name in event:
            lines.append(f"{name}: {event[name]}")
    if event.get("detail"):
        lines.append(str(event["detail"]))
    return "\n".join(line for line in lines if line)
