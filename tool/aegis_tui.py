#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import MouseDown, MouseMove, MouseUp
from textual.widgets import Button, Collapsible, DataTable, Footer, Header, RichLog, Static, TabbedContent, TabPane

from tool.aegis_events import (
    EventLogTailer,
    FlowRecord,
    FlowStore,
    body_detail_text,
    copy_value_for_id,
    event_detail_text,
    event_headers_text,
    event_raw_text,
    format_ts,
    json_block,
    log_event_text,
    pretty_body_text,
    raw_events_text,
    session_fields,
    session_text,
)
from tool.aegis_runtime import EmbeddedMitmRunner, build_parser as build_runtime_parser, prepare_mitm_confdir


class AegisMitmTui(App[None]):
    CSS = """
    Screen {
        layout: vertical;
    }
    #status {
        height: 3;
        padding: 0 1;
        background: $surface;
    }
    #main {
        height: 1fr;
    }
    #flows {
        width: 46;
        min-width: 30;
        max-width: 80;
    }
    #details {
        width: 54;
        border-left: solid $primary;
    }
    #splitter {
        width: 1;
        background: $primary;
    }
    #detail-tabs {
        height: 1fr;
    }
    .copy-toolbar {
        height: auto;
        padding: 0 1;
    }
    .copy-toolbar Button {
        margin: 0 1 0 0;
        min-width: 8;
    }
    .detail-pane {
        height: 1fr;
        padding: 0 1;
    }
    #log-panel {
        height: auto;
        max-height: 13;
    }
    #log {
        height: 10;
        padding: 0 1;
    }
    DataTable {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "clear", "Clear"),
        ("l", "toggle_log", "Logs"),
    ]

    def __init__(self, args: Any) -> None:
        super().__init__()
        self.args = args
        self.event_log = Path(args.event_log).resolve()
        self.dump_dir = Path(args.dump_dir).resolve()
        self.upstream_proxy = args.upstream_proxy or "http://127.0.0.1:9370"
        self.runner: EmbeddedMitmRunner | None = None
        self.tailer = EventLogTailer(self.event_log)
        self.store = FlowStore()
        self.row_by_flow: dict[str, str] = {}
        self.selected_flow_id: str | None = None
        self.dragging_splitter = False
        self.left_width = 46

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("starting embedded mitmproxy...", id="status")
        with Horizontal(id="main"):
            with Vertical(id="flows"):
                table = DataTable(id="table")
                table.cursor_type = "row"
                yield table
            yield Static("", id="splitter")
            with Vertical(id="details"):
                with TabbedContent(id="detail-tabs"):
                    with TabPane("Overview", id="tab-overview"):
                        with Horizontal(classes="copy-toolbar"):
                            yield Button("URL", id="copy-overview-url")
                            yield Button("Req Headers", id="copy-overview-request-headers")
                            yield Button("Req Body", id="copy-overview-request-body")
                            yield Button("Res Headers", id="copy-overview-response-headers")
                            yield Button("Res Body", id="copy-overview-response-body")
                        with VerticalScroll(classes="detail-pane"):
                            yield Static("Select a request", id="overview-detail")
                    with TabPane("Request", id="tab-request"):
                        with Horizontal(classes="copy-toolbar"):
                            yield Button("URL", id="copy-request-url")
                            yield Button("Headers", id="copy-request-headers")
                            yield Button("Body", id="copy-request-body")
                            yield Button("Raw", id="copy-request-raw")
                        with VerticalScroll(classes="detail-pane"):
                            yield Static("Select a request", id="request-detail")
                    with TabPane("Response", id="tab-response"):
                        with Horizontal(classes="copy-toolbar"):
                            yield Button("Headers", id="copy-response-headers")
                            yield Button("Body", id="copy-response-body")
                            yield Button("Raw", id="copy-response-raw")
                        with VerticalScroll(classes="detail-pane"):
                            yield Static("Select a request", id="response-detail")
                    with TabPane("Request Body", id="tab-request-body"):
                        with Horizontal(classes="copy-toolbar"):
                            yield Button("Copy Body", id="copy-request-body-tab")
                            yield Button("Copy URL", id="copy-request-body-url")
                        with VerticalScroll(classes="detail-pane"):
                            yield Static("Select a request", id="request-body-detail")
                    with TabPane("Response Body", id="tab-response-body"):
                        with Horizontal(classes="copy-toolbar"):
                            yield Button("Copy Body", id="copy-response-body-tab")
                            yield Button("Copy URL", id="copy-response-body-url")
                        with VerticalScroll(classes="detail-pane"):
                            yield Static("Select a request", id="response-body-detail")
                    with TabPane("Raw", id="tab-raw"):
                        with Horizontal(classes="copy-toolbar"):
                            yield Button("Events", id="copy-raw-events")
                            yield Button("Req Raw", id="copy-raw-request")
                            yield Button("Res Raw", id="copy-raw-response")
                        with VerticalScroll(classes="detail-pane"):
                            yield Static("Select a request", id="raw-detail")
                    with TabPane("Session", id="tab-session"):
                        with Horizontal(classes="copy-toolbar"):
                            yield Button("Session", id="copy-session-info")
                            yield Button("Session Key", id="copy-session-key")
                            yield Button("R Plain", id="copy-session-r-plain")
                        with VerticalScroll(classes="detail-pane"):
                            yield Static("Select a request", id="session-detail")
        with Collapsible(title="Logs", collapsed=False, id="log-panel"):
            yield RichLog(id="log", wrap=True, highlight=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#table", DataTable)
        table.add_column("Time", key="time", width=8)
        table.add_column("Method", key="method", width=7)
        table.add_column("HTTP", key="http", width=5)
        table.add_column("State", key="state", width=28)
        table.add_column("Path", key="path")
        self.event_log.parent.mkdir(parents=True, exist_ok=True)
        self.dump_dir.mkdir(parents=True, exist_ok=True)
        self.event_log.write_text("", encoding="utf-8")
        self._start_mitmproxy()
        self.set_interval(0.25, self._poll_events)
        self._apply_splitter_width()

    def action_clear(self) -> None:
        self.query_one("#table", DataTable).clear()
        self.query_one("#log", RichLog).clear()
        self.row_by_flow.clear()
        self.store.clear()
        self.selected_flow_id = None
        self._render_selected_flow()

    def on_mouse_down(self, event: MouseDown) -> None:
        splitter = self.query_one("#splitter", Static)
        if event.widget is splitter:
            self.dragging_splitter = True
            self.capture_mouse()

    def on_mouse_move(self, event: MouseMove) -> None:
        if not self.dragging_splitter:
            return
        total = max(80, self.size.width)
        left = max(30, min(event.x, total - 30))
        self.left_width = left
        self._apply_splitter_width()

    def on_mouse_up(self, event: MouseUp) -> None:
        if self.dragging_splitter:
            self.dragging_splitter = False
            self.capture_mouse(None)

    def action_toggle_log(self) -> None:
        panel = self.query_one("#log-panel", Collapsible)
        panel.collapsed = not panel.collapsed

    def on_data_table_row_highlighted(self, message: DataTable.RowHighlighted) -> None:
        if message.data_table.id != "table":
            return
        self.selected_flow_id = self._row_key_value(message.row_key)
        self._render_selected_flow()

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        if message.data_table.id != "table":
            return
        self.selected_flow_id = self._row_key_value(message.row_key)
        self._render_selected_flow()

    def on_button_pressed(self, message: Button.Pressed) -> None:
        button_id = message.button.id or ""
        if not button_id.startswith("copy-"):
            return
        value = self._copy_value_for_button(button_id)
        if not value:
            self.notify("Nothing to copy for the selected request.", title="Copy", severity="warning")
            return
        self.copy_to_clipboard(value)
        self.notify("Copied to clipboard.", title="Copy")

    def on_unmount(self) -> None:
        if self.runner is not None:
            self.runner.stop()

    def _start_mitmproxy(self) -> None:
        try:
            confdir = prepare_mitm_confdir(self.args)
            self.runner = EmbeddedMitmRunner(self.args, confdir)
            self.runner.start()
        except Exception as exc:
            self._log(f"embedded mitmproxy failed: {exc}")
            self.query_one("#status", Static).update("embedded mitmproxy failed")
            return
        self.query_one("#status", Static).update(
            f"embedded mitmproxy listening on {self.args.listen_host}:{self.args.listen_port} | "
            f"upstream: {self.upstream_proxy}"
        )
        self._log(f"event log: {self.event_log}")
        if confdir is not None:
            self._log(f"mitm CA confdir: {confdir}")

    def _poll_events(self) -> None:
        for event in self.tailer.read_new():
            self._add_event(event)

    def _add_event(self, event: dict[str, Any]) -> None:
        table = self.query_one("#table", DataTable)
        flow, is_new = self.store.apply(event)

        row_key = flow.flow_id
        values = (
            format_ts(flow.last_ts, include_date=False),
            flow.method,
            flow.http_status,
            flow.display_status,
            flow.display_path,
        )
        if is_new:
            table.add_row(*values, key=row_key)
            self.row_by_flow[flow.flow_id] = row_key
            if self.selected_flow_id is None:
                self.selected_flow_id = flow.flow_id
                table.move_cursor(row=table.row_count - 1)
                self._render_selected_flow()
        else:
            for column_key, value in zip(("time", "method", "http", "state", "path"), values, strict=True):
                table.update_cell(row_key, column_key, value, update_width=column_key == "path")

        self._write_log_event(event)
        if self.selected_flow_id == flow.flow_id:
            self._render_selected_flow()

    def _write_log_event(self, event: dict[str, Any]) -> None:
        self.query_one("#log", RichLog).write(log_event_text(event))

    def _render_selected_flow(self) -> None:
        flow = self.store.get(self.selected_flow_id)
        if flow is None:
            empty = "Select a request"
            for widget_id in (
                "#overview-detail",
                "#request-detail",
                "#response-detail",
                "#request-body-detail",
                "#response-body-detail",
                "#raw-detail",
                "#session-detail",
            ):
                self.query_one(widget_id, Static).update(empty)
            return

        self.query_one("#overview-detail", Static).update(self._overview_renderable(flow))
        self.query_one("#request-detail", Static).update(self._event_renderable("Request", flow.request_event))
        self.query_one("#response-detail", Static).update(self._event_renderable("Response", flow.response_event or flow.key_event))
        self.query_one("#request-body-detail", Static).update(self._body_renderable("Request Body", flow.request_event))
        self.query_one("#response-body-detail", Static).update(self._body_renderable("Response Body", flow.response_event or flow.key_event))
        self.query_one("#raw-detail", Static).update(self._raw_renderable(flow))
        self.query_one("#session-detail", Static).update(self._session_renderable(flow))

    def _overview_renderable(self, flow: FlowRecord) -> Panel:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="cyan", no_wrap=True)
        table.add_column()
        table.add_row("Flow", flow.flow_id)
        table.add_row("Protocol", flow.display_protocol)
        table.add_row("Method", flow.method or "-")
        table.add_row("URL", flow.url or "-")
        table.add_row("HTTP", flow.http_status or "-")
        table.add_row("State", flow.display_status or "-")
        table.add_row("Events", str(len(flow.events)))
        table.add_row("First Seen", format_ts(flow.first_ts))
        table.add_row("Updated", format_ts(flow.last_ts))
        dump_paths = [str(event.get("dump_path")) for event in flow.events if event.get("dump_path")]
        if dump_paths:
            table.add_row("Dumps", "\n".join(dump_paths))
        return Panel(table, title="Request Overview", border_style="cyan")

    def _event_renderable(self, title: str, event: dict[str, Any] | None) -> Panel:
        if event is None:
            return Panel("No data for this tab yet.", title=title, border_style="dim")
        body = Table.grid(padding=(0, 2))
        body.add_column(style="cyan", no_wrap=True)
        body.add_column()
        for name in ("kind", "status", "protocol", "operation", "method", "url", "http_status", "content_type", "content_encoding", "body_len", "dump_path"):
            if name in event:
                body.add_row(name, str(event[name]))
        if "request_headers" in event:
            body.add_row("request headers", event_headers_text(event, "request_headers"))
        if "response_headers" in event:
            body.add_row("response headers", event_headers_text(event, "response_headers"))
        if event.get("detail"):
            body.add_row("body", self._pretty_body(str(event["detail"])))
        return Panel(body, title=title, border_style="green")

    def _body_renderable(self, title: str, event: dict[str, Any] | None) -> Panel:
        if event is None:
            return Panel("No payload yet.", title=title, border_style="dim")
        payload = event.get("body") or event.get("detail") or ""
        body_format = str(event.get("body_format") or "")
        if body_format == "body:b64":
            subtitle = "base64 decoded body"
        elif body_format:
            subtitle = body_format
        else:
            subtitle = "payload"
        return Panel(self._pretty_body(str(payload)), title=f"{title} ({subtitle})", border_style="blue")

    def _raw_renderable(self, flow: FlowRecord) -> Panel:
        body = Table.grid(padding=(0, 2))
        body.add_column(style="cyan", no_wrap=True)
        body.add_column()
        for label, event in (("request raw", flow.request_event), ("response raw", flow.response_event)):
            if event is None:
                continue
            if event.get("raw_dump_path"):
                body.add_row(f"{label} dump", str(event["raw_dump_path"]))
            if event.get("raw_detail"):
                body.add_row(f"{label} preview", str(event["raw_detail"]))
        body.add_row("events", Syntax(raw_events_text(flow), "json", word_wrap=True))
        return Panel(body, title="Raw Events / Bodies", border_style="magenta")

    def _session_renderable(self, flow: FlowRecord) -> Panel:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="cyan", no_wrap=True)
        table.add_column()
        for name, value in session_fields(flow).items():
            table.add_row(name, str(value) if value else "-")
        return Panel(table, title="Session / Key Info", border_style="yellow")

    def _copy_value_for_button(self, button_id: str) -> str:
        return copy_value_for_id(self.store.get(self.selected_flow_id), button_id)

    def _log(self, message: str) -> None:
        self.query_one("#log", RichLog).write(message)

    def _apply_splitter_width(self) -> None:
        try:
            flows = self.query_one("#flows", Vertical)
            details = self.query_one("#details", Vertical)
            splitter = self.query_one("#splitter", Static)
        except Exception:
            return
        total = max(80, self.size.width)
        left = max(30, min(self.left_width, total - 30))
        splitter_width = 1
        flows.styles.width = left
        details.styles.width = total - left - splitter_width
        splitter.styles.width = splitter_width
        splitter.update("|")

    @staticmethod
    def _row_key_value(row_key: Any) -> str:
        return str(getattr(row_key, "value", row_key))

    @staticmethod
    def _json_block(value: Any) -> str:
        return json_block(value)

    @staticmethod
    def _pretty_body(value: str) -> Syntax | str:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value
        return Syntax(json.dumps(parsed, ensure_ascii=False, indent=2), "json", word_wrap=True)

    @staticmethod
    def _plain_detail_text(flow: FlowRecord, tab_name: str) -> str:
        if tab_name == "overview":
            from tool.aegis_events import overview_text

            return overview_text(flow)
        if tab_name == "request":
            return event_detail_text("Request", flow.request_event)
        if tab_name == "response":
            return event_detail_text("Response", flow.response_event or flow.key_event)
        if tab_name == "request-body":
            return body_detail_text("Request Body", flow.request_event)
        if tab_name == "response-body":
            return body_detail_text("Response Body", flow.response_event or flow.key_event)
        if tab_name == "raw":
            from tool.aegis_events import raw_detail_text

            return raw_detail_text(flow)
        if tab_name == "session":
            from tool.aegis_events import session_detail_text

            return session_detail_text(flow)
        return session_text(flow)


def build_parser() -> Any:
    return build_runtime_parser(description="Netrace TUI for encrypted /xeapi and /eapi traffic")


def main() -> None:
    args = build_parser().parse_args()
    AegisMitmTui(args).run()


if __name__ == "__main__":
    main()
