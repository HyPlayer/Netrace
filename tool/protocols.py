#!/usr/bin/env python3
from __future__ import annotations

from typing import Protocol

from mitmproxy import http

from tool.mitm_context import MitmContext


NETRACE_PROTOCOL = "netrace_protocol"
NETRACE_KEY_HANDLER = "netrace_key_handler"


class ProtocolHandler(Protocol):
    name: str

    def matches_request(self, flow: http.HTTPFlow) -> bool:
        ...

    def is_key_flow(self, flow: http.HTTPFlow, ctx: MitmContext) -> bool:
        ...

    def handle_key_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        ...

    def handle_key_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        ...

    def handle_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        ...

    def handle_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        ...


class BaseProtocolHandler:
    name = "base"

    def matches_request(self, flow: http.HTTPFlow) -> bool:
        return False

    def is_key_flow(self, flow: http.HTTPFlow, ctx: MitmContext) -> bool:
        return False

    def handle_key_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        return

    def handle_key_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        return

    def handle_request(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        return

    def handle_response(self, flow: http.HTTPFlow, ctx: MitmContext) -> None:
        return


class ProtocolRegistry:
    def __init__(self, handlers: list[ProtocolHandler]) -> None:
        self.handlers = handlers
        self.by_name = {handler.name: handler for handler in handlers}

    def key_handler_for(self, flow: http.HTTPFlow, ctx: MitmContext) -> ProtocolHandler | None:
        for handler in self.handlers:
            if handler.is_key_flow(flow, ctx):
                return handler
        return None

    def request_handler_for(self, flow: http.HTTPFlow) -> ProtocolHandler | None:
        for handler in self.handlers:
            if handler.matches_request(flow):
                return handler
        return None

    def get(self, name: str | None) -> ProtocolHandler | None:
        if name is None:
            return None
        return self.by_name.get(name)
