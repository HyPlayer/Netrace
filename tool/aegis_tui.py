#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import shutil
from dataclasses import dataclass, field
import json
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

from rich.panel import Panel
from rich.pretty import Pretty
from rich.syntax import Syntax
from rich.table import Table
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import MouseDown, MouseMove, MouseUp
from textual.widgets import Button, Collapsible, DataTable, Footer, Header, RichLog, Static, TabbedContent, TabPane

ROOT = Path(__file__).resolve().parents[1]
TOOL_DIR = Path(__file__).resolve().parent
RUN_DIR = TOOL_DIR / "runs"
DEFAULT_CA_PEM = TOOL_DIR / "capture-ca.pem"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class EmbeddedMitmRunner:
    def __init__(self, args: argparse.Namespace, confdir: Path | None) -> None:
        from tool.aegis_mitm_addon import AegisMitmAddon

        self.args = args
        self.confdir = confdir
        self.master: DumpMaster | None = None
        self.thread: threading.Thread | None = None
        self.started = threading.Event()
        self.stopped = threading.Event()
        self.error: BaseException | None = None
        self.addon = AegisMitmAddon()
        self.lifecycle = _LifecycleSignal(self.started, self.stopped)
        self.socks_bridge: Socks5HttpBridge | None = None

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="aegis-mitmproxy", daemon=True)
        self.thread.start()
        self.started.wait(timeout=5)
        if self.error is not None:
            raise RuntimeError("embedded mitmproxy failed to start") from self.error

    def stop(self) -> None:
        if self.master is not None:
            self.master.shutdown()
        if self.thread is not None:
            self.thread.join(timeout=5)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            install_ca_ski_authority_key_patch()
            upstream_proxy = self.args.upstream_proxy
            if upstream_proxy.startswith("socks5://"):
                self.socks_bridge = Socks5HttpBridge(upstream_proxy)
                upstream_proxy = loop.run_until_complete(self.socks_bridge.start())
            opts = options.Options(
                listen_host=self.args.listen_host,
                listen_port=self.args.listen_port,
                mode=[f"upstream:{upstream_proxy}"],
                ssl_insecure=self.args.ssl_insecure,
            )
            if self.confdir is not None:
                opts.update(confdir=str(self.confdir))

            self.master = DumpMaster(opts, loop=loop, with_termlog=False, with_dumper=False)
            self.master.addons.add(self.lifecycle, self.addon)
            self.master.options.update(
                aegis_static_key=self.args.static_key,
                aegis_sign_key=self.args.sign_key,
                aegis_dump_dir=str(Path(self.args.dump_dir).resolve()),
                aegis_event_log=str(Path(self.args.event_log).resolve()),
                aegis_response_mode=self.args.response_mode,
                aegis_force_key_refresh_on_miss=self.args.force_key_refresh_on_miss,
                aegis_public_key_ttl_seconds=self.args.public_key_ttl_seconds,
                aegis_proxy_private_key_file=self.args.proxy_private_key_file,
                aegis_hkdf_salt=self.args.hkdf_salt,
                aegis_hkdf_info=self.args.hkdf_info,
            )
            loop.run_until_complete(self.master.run())
            if not self.lifecycle.running_seen:
                self.error = RuntimeError("mitmproxy stopped before it became ready")
                self.started.set()
        except BaseException as exc:
            self.error = exc
            self.started.set()
        finally:
            if self.socks_bridge is not None:
                try:
                    loop.run_until_complete(self.socks_bridge.close())
                except Exception:
                    pass
            pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            self.stopped.set()
            loop.close()


class Socks5HttpBridge:
    def __init__(self, proxy_url: str) -> None:
        parsed = urllib.parse.urlparse(proxy_url)
        if parsed.scheme != "socks5" or not parsed.hostname or not parsed.port:
            raise ValueError(f"invalid SOCKS5 proxy URL: {proxy_url}")
        self.socks_host = parsed.hostname
        self.socks_port = parsed.port
        self.username = urllib.parse.unquote(parsed.username) if parsed.username else None
        self.password = urllib.parse.unquote(parsed.password) if parsed.password else None
        self.server: asyncio.AbstractServer | None = None

    async def start(self) -> str:
        self.server = await asyncio.start_server(self._handle_client, "127.0.0.1", 0)
        sock = self.server.sockets[0]
        host, port = sock.getsockname()[:2]
        return f"http://{host}:{port}"

    async def close(self) -> None:
        if self.server is None:
            return
        self.server.close()
        await self.server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        remote_reader: asyncio.StreamReader | None = None
        remote_writer: asyncio.StreamWriter | None = None
        try:
            header = await reader.readuntil(b"\r\n\r\n")
            first, rest = header.split(b"\r\n", 1)
            parts = first.decode("latin1").split(" ", 2)
            if len(parts) != 3:
                raise ValueError("invalid proxy request line")
            method, target, version = parts
            if method.upper() == "CONNECT":
                host, port = self._split_host_port(target, 443)
                remote_reader, remote_writer = await self._connect_via_socks(host, port)
                writer.write(f"{version} 200 Connection established\r\n\r\n".encode("ascii"))
                await writer.drain()
            else:
                parsed = urllib.parse.urlsplit(target)
                if not parsed.hostname:
                    raise ValueError("expected absolute-form HTTP proxy request")
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                remote_reader, remote_writer = await self._connect_via_socks(host, port)
                rewritten = f"{method} {path} {version}\r\n".encode("latin1")
                remote_writer.write(rewritten + self._strip_proxy_headers(rest))
                await remote_writer.drain()
            await self._pipe_both(reader, writer, remote_reader, remote_writer)
        except Exception:
            if not writer.is_closing():
                try:
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    await writer.drain()
                except Exception:
                    pass
        finally:
            for stream in (remote_writer, writer):
                if stream and not stream.is_closing():
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except Exception:
                        pass

    async def _connect_via_socks(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.open_connection(self.socks_host, self.socks_port)
        methods = [0x00]
        if self.username is not None and self.password is not None:
            methods.append(0x02)
        writer.write(bytes([0x05, len(methods), *methods]))
        await writer.drain()
        version, method = await reader.readexactly(2)
        if version != 0x05 or method == 0xFF:
            raise OSError("SOCKS5 proxy rejected authentication methods")
        if method == 0x02:
            user = self.username.encode("utf-8") if self.username else b""
            password = self.password.encode("utf-8") if self.password else b""
            writer.write(bytes([0x01, len(user)]) + user + bytes([len(password)]) + password)
            await writer.drain()
            auth_version, status = await reader.readexactly(2)
            if auth_version != 0x01 or status != 0x00:
                raise OSError("SOCKS5 username/password authentication failed")

        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            raise ValueError("target host name is too long for SOCKS5")
        writer.write(b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + port.to_bytes(2, "big"))
        await writer.drain()
        reply = await reader.readexactly(4)
        if reply[0] != 0x05 or reply[1] != 0x00:
            raise OSError(f"SOCKS5 connect failed with code {reply[1]}")
        atyp = reply[3]
        if atyp == 0x01:
            await reader.readexactly(4)
        elif atyp == 0x03:
            length = (await reader.readexactly(1))[0]
            await reader.readexactly(length)
        elif atyp == 0x04:
            await reader.readexactly(16)
        else:
            raise OSError("SOCKS5 proxy returned an invalid address type")
        await reader.readexactly(2)
        return reader, writer

    @staticmethod
    def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
        if target.startswith("["):
            host, _, tail = target[1:].partition("]")
            port = int(tail[1:]) if tail.startswith(":") else default_port
            return host, port
        host, sep, port_text = target.rpartition(":")
        if sep:
            return host, int(port_text)
        return target, default_port

    @staticmethod
    def _strip_proxy_headers(header_tail: bytes) -> bytes:
        out: list[bytes] = []
        for line in header_tail.split(b"\r\n"):
            if line.lower().startswith(b"proxy-connection:"):
                continue
            out.append(line)
        return b"\r\n".join(out)

    async def _pipe_both(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
    ) -> None:
        async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            while not reader.at_eof():
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
            if not writer.is_closing():
                writer.close()

        await asyncio.gather(
            pipe(client_reader, remote_writer),
            pipe(remote_reader, client_writer),
            return_exceptions=True,
        )


def install_ca_ski_authority_key_patch() -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    from mitmproxy import certs

    if getattr(certs, "_aegis_ca_ski_authority_key_patch", False):
        return

    def dummy_cert_with_ca_ski_aki(
        privkey,
        cacert: x509.Certificate,
        commonname: str | None,
        sans,
        organization: str | None = None,
    ):
        builder = x509.CertificateBuilder()
        builder = builder.issuer_name(cacert.subject)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        builder = builder.public_key(cacert.public_key())

        now = certs.datetime.datetime.now()
        builder = builder.not_valid_before(now - certs.datetime.timedelta(days=2))
        builder = builder.not_valid_after(now + certs.CERT_EXPIRY)

        subject = []
        is_valid_commonname = commonname is not None and len(commonname) < 64
        if is_valid_commonname:
            subject.append(x509.NameAttribute(NameOID.COMMON_NAME, commonname))
        if organization is not None:
            subject.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))
        builder = builder.subject_name(x509.Name(subject))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.add_extension(
            x509.SubjectAlternativeName(certs._fix_legacy_sans(sans)),
            critical=not is_valid_commonname,
        )

        try:
            ca_ski = cacert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            authority_key = x509.AuthorityKeyIdentifier(
                key_identifier=ca_ski,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            )
        except x509.ExtensionNotFound:
            authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key())
        builder = builder.add_extension(authority_key, critical=False)

        cert = builder.sign(private_key=privkey, algorithm=hashes.SHA256())
        return certs.Cert(cert)

    certs.dummy_cert = dummy_cert_with_ca_ski_aki
    certs._aegis_ca_ski_authority_key_patch = True


class _LifecycleSignal:
    def __init__(self, started: threading.Event, stopped: threading.Event) -> None:
        self.started = started
        self.stopped = stopped
        self.running_seen = False

    def running(self) -> None:
        self.running_seen = True
        self.started.set()

    def done(self) -> None:
        self.stopped.set()


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

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__()
        self.args = args
        self.event_log = Path(args.event_log).resolve()
        self.dump_dir = Path(args.dump_dir).resolve()
        self.mitm_confdir = Path(args.confdir).resolve() if args.confdir else None
        ca_pem = args.ca_pem or str(DEFAULT_CA_PEM)
        self.ca_pem = Path(ca_pem).resolve() if ca_pem else None
        self.upstream_proxy = args.upstream_proxy or "http://127.0.0.1:9370"
        self.runner: EmbeddedMitmRunner | None = None
        self.stop_event = threading.Event()
        self.offset = 0
        self.row_by_flow: dict[str, str] = {}
        self.flows: dict[str, FlowRecord] = {}
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
        self.flows.clear()
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
        self.stop_event.set()
        if self.runner is not None:
            self.runner.stop()

    def _start_mitmproxy(self) -> None:
        confdir = self._prepare_confdir()
        try:
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

    def _prepare_confdir(self) -> Path | None:
        if self.ca_pem is None and self.mitm_confdir is None:
            return None
        confdir = self.mitm_confdir or (RUN_DIR / "mitm_confdir")
        confdir.mkdir(parents=True, exist_ok=True)
        if self.ca_pem is not None:
            if not self.ca_pem.exists():
                raise FileNotFoundError(f"CA PEM not found: {self.ca_pem}")
            target = confdir / "mitmproxy-ca.pem"
            if self.ca_pem.resolve() != target.resolve():
                shutil.copyfile(self.ca_pem, target)
        return confdir

    def _poll_events(self) -> None:
        if not self.event_log.exists():
            return
        with self.event_log.open("r", encoding="utf-8") as f:
            f.seek(self.offset)
            lines = f.readlines()
            self.offset = f.tell()
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._add_event(event)

    def _add_event(self, event: dict[str, Any]) -> None:
        table = self.query_one("#table", DataTable)
        ts = time.strftime("%H:%M:%S", time.localtime(float(event.get("ts", time.time()))))
        flow_id = str(event.get("flow_id") or f"event:{event.get('ts', time.time())}")
        kind = str(event.get("kind", ""))
        status = str(event.get("status", ""))
        flow = self.flows.get(flow_id)
        if flow is None:
            event_ts = float(event.get("ts", time.time()))
            flow = FlowRecord(flow_id=flow_id, first_ts=event_ts, last_ts=event_ts)
            self.flows[flow_id] = flow
        flow.apply(event)

        row_key = flow_id
        values = (
            ts,
            flow.method,
            flow.http_status,
            flow.display_status,
            flow.display_path,
        )
        if flow_id not in self.row_by_flow:
            table.add_row(*values, key=row_key)
            self.row_by_flow[flow_id] = row_key
            if self.selected_flow_id is None:
                self.selected_flow_id = flow_id
                table.move_cursor(row=table.row_count - 1)
                self._render_selected_flow()
        else:
            for column_key, value in zip(("time", "method", "http", "state", "path"), values, strict=True):
                table.update_cell(row_key, column_key, value, update_width=column_key == "path")

        self._write_log_event(ts, event)
        if self.selected_flow_id == flow_id:
            self._render_selected_flow()

    def _write_log_event(self, ts: str, event: dict[str, Any]) -> None:
        log = self.query_one("#log", RichLog)
        kind = str(event.get("kind", ""))
        status = str(event.get("status", ""))
        path = str(event.get("path") or event.get("url") or "")
        log.write(f"[bold cyan]{ts} {kind}[/] [yellow]{status}[/]\n{path}")
        for name in (
            "version",
            "sk",
            "session_id",
            "session_key",
            "r_plain",
            "signature_ok",
            "body_encoding",
            "plaintext_encoding",
            "public_key_ttl_seconds",
            "dump_path",
        ):
            if name in event:
                log.write(f"{name}: {event[name]}")
        if event.get("detail"):
            log.write(event["detail"])

    def _render_selected_flow(self) -> None:
        flow = self.flows.get(self.selected_flow_id or "")
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
        table.add_row("Method", flow.method or "-")
        table.add_row("URL", flow.url or "-")
        table.add_row("HTTP", flow.http_status or "-")
        table.add_row("State", flow.display_status or "-")
        table.add_row("Events", str(len(flow.events)))
        table.add_row("First Seen", self._format_ts(flow.first_ts))
        table.add_row("Updated", self._format_ts(flow.last_ts))
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
        for name in ("kind", "status", "method", "url", "http_status", "content_type", "content_encoding", "body_len", "dump_path"):
            if name in event:
                body.add_row(name, str(event[name]))
        if "request_headers" in event:
            body.add_row("request headers", self._json_block(event["request_headers"]))
        if "response_headers" in event:
            body.add_row("response headers", self._json_block(event["response_headers"]))
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
        raw = json.dumps(flow.events, ensure_ascii=False, indent=2, default=str)
        body.add_row("events", Syntax(raw, "json", word_wrap=True))
        return Panel(body, title="Raw Events / Bodies", border_style="magenta")

    def _session_renderable(self, flow: FlowRecord) -> Panel:
        table = Table.grid(padding=(0, 2))
        table.add_column(style="cyan", no_wrap=True)
        table.add_column()
        session_fields = {
            "session_id": flow.session_id,
            "session_key": flow.session_key,
            "r_plain": flow.r_plain,
        }
        for event in flow.events:
            for name in (
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
            ):
                if name in event:
                    session_fields[name] = str(event[name])
        for name, value in session_fields.items():
            table.add_row(name, str(value) if value else "-")
        return Panel(table, title="Session / Key Info", border_style="yellow")

    def _copy_value_for_button(self, button_id: str) -> str:
        flow = self.flows.get(self.selected_flow_id or "")
        if flow is None:
            return ""
        request_event = flow.request_event
        response_event = flow.response_event or flow.key_event

        if button_id in {"copy-overview-url", "copy-request-url", "copy-request-body-url", "copy-response-body-url"}:
            return flow.url
        if button_id == "copy-overview-request-headers" or button_id == "copy-request-headers":
            return self._event_headers_text(request_event, "request_headers")
        if button_id == "copy-overview-response-headers" or button_id == "copy-response-headers":
            return self._event_headers_text(response_event, "response_headers")
        if button_id in {"copy-overview-request-body", "copy-request-body", "copy-request-body-tab"}:
            return self._event_body_text(request_event)
        if button_id in {"copy-overview-response-body", "copy-response-body", "copy-response-body-tab"}:
            return self._event_body_text(response_event)
        if button_id in {"copy-request-raw", "copy-raw-request"}:
            return self._event_raw_text(request_event)
        if button_id in {"copy-response-raw", "copy-raw-response"}:
            return self._event_raw_text(response_event)
        if button_id == "copy-raw-events":
            return json.dumps(flow.events, ensure_ascii=False, indent=2, default=str)
        if button_id == "copy-session-info":
            return self._session_text(flow)
        if button_id == "copy-session-key":
            return flow.session_key
        if button_id == "copy-session-r-plain":
            return flow.r_plain
        return ""

    def _event_headers_text(self, event: dict[str, Any] | None, field: str) -> str:
        if event is None or field not in event:
            return ""
        return self._json_block(event[field])

    @staticmethod
    def _event_body_text(event: dict[str, Any] | None) -> str:
        if event is None:
            return ""
        value = event.get("body")
        if value is None:
            value = event.get("detail")
        return str(value) if value is not None else ""

    @staticmethod
    def _event_raw_text(event: dict[str, Any] | None) -> str:
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

    def _session_text(self, flow: FlowRecord) -> str:
        session_fields: dict[str, str] = {
            "session_id": flow.session_id,
            "session_key": flow.session_key,
            "r_plain": flow.r_plain,
        }
        for event in flow.events:
            for name in (
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
            ):
                if name in event:
                    session_fields[name] = str(event[name])
        return self._json_block({name: value for name, value in session_fields.items() if value})

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
        splitter.update("│")

    @staticmethod
    def _format_ts(value: float) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))

    @staticmethod
    def _row_key_value(row_key: Any) -> str:
        return str(getattr(row_key, "value", row_key))

    @staticmethod
    def _json_block(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, indent=2, default=str)

    @staticmethod
    def _pretty_body(value: str) -> Syntax | str:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value
        return Syntax(json.dumps(parsed, ensure_ascii=False, indent=2), "json", word_wrap=True)


def build_parser() -> argparse.ArgumentParser:
    from tool.aegis_mitm_core import DEFAULT_SIGN_KEY_B64, DEFAULT_STATIC_KEY_HEX

    parser = argparse.ArgumentParser(description="Textual TUI for the Aegis /xeapi MITM addon")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=8080)
    parser.add_argument("--confdir", default="", help="mitmproxy config directory containing mitmproxy-ca.pem")
    parser.add_argument("--ca-pem", default=str(DEFAULT_CA_PEM), help="Path to a custom mitmproxy-ca.pem to load into confdir")
    parser.add_argument("--upstream-proxy", default="http://127.0.0.1:9370", help="Upstream proxy, e.g. http://127.0.0.1:9370 or socks5://127.0.0.1:9370")
    parser.add_argument("--ssl-insecure", dest="ssl_insecure", action="store_true", default=True, help="Do not verify upstream TLS certificates.")
    parser.add_argument("--ssl-verify-upstream", dest="ssl_insecure", action="store_false", help="Verify upstream TLS certificates.")
    parser.add_argument("--static-key", default="hex:" + DEFAULT_STATIC_KEY_HEX)
    parser.add_argument("--sign-key", default=DEFAULT_SIGN_KEY_B64)
    parser.add_argument(
        "--proxy-private-key-file",
        default=str(TOOL_DIR / "proxy-server-x25519.key"),
        help="Persistent X25519 private key used as the forged Aegis server key.",
    )
    parser.add_argument("--hkdf-salt", default="")
    parser.add_argument("--hkdf-info", default="")
    parser.add_argument("--response-mode", choices=["auto", "legacy", "session"], default="auto")
    parser.add_argument("--no-force-key-refresh-on-miss", dest="force_key_refresh_on_miss", action="store_false")
    parser.set_defaults(force_key_refresh_on_miss=True)
    parser.add_argument("--public-key-ttl-seconds", type=int, default=600)
    parser.add_argument("--event-log", default=str(RUN_DIR / "events.jsonl"))
    parser.add_argument("--dump-dir", default=str(RUN_DIR / "dumps"))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    AegisMitmTui(args).run()


if __name__ == "__main__":
    main()
