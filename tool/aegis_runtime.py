#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import shutil
import sys
import threading
import urllib.parse
from pathlib import Path

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

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
        self.thread = threading.Thread(target=self._run, name="netrace-mitmproxy", daemon=True)
        self.thread.start()
        if not self.started.wait(timeout=5):
            self.stop()
            raise TimeoutError("embedded mitmproxy did not become ready within 5 seconds")
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
                weapi_private_key_file=self.args.weapi_private_key_file,
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


def prepare_mitm_confdir(args: argparse.Namespace) -> Path | None:
    ca_pem_arg = getattr(args, "ca_pem", None)
    ca_pem = Path(ca_pem_arg or str(DEFAULT_CA_PEM)).resolve() if ca_pem_arg or DEFAULT_CA_PEM else None
    mitm_confdir = Path(args.confdir).resolve() if getattr(args, "confdir", "") else None
    if ca_pem is None and mitm_confdir is None:
        return None
    confdir = mitm_confdir or (RUN_DIR / "mitm_confdir")
    confdir.mkdir(parents=True, exist_ok=True)
    if ca_pem is not None:
        if not ca_pem.exists():
            raise FileNotFoundError(
                f"CA PEM not found: {ca_pem}. Create tool/capture-ca.pem or pass --ca-pem PATH."
            )
        target = confdir / "mitmproxy-ca.pem"
        if ca_pem.resolve() != target.resolve():
            shutil.copyfile(ca_pem, target)
    return confdir


def build_parser(*, description: str, include_gui_options: bool = False) -> argparse.ArgumentParser:
    from tool.aegis_mitm_core import DEFAULT_SIGN_KEY_B64, DEFAULT_STATIC_KEY_HEX

    parser = argparse.ArgumentParser(description=description)
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
    parser.add_argument(
        "--weapi-private-key-file",
        default=str(TOOL_DIR / "weapi-rsa-private.key"),
        help="Persistent RSA private key used as the forged /weapi web RSA key.",
    )
    parser.add_argument("--hkdf-salt", default="")
    parser.add_argument("--hkdf-info", default="")
    parser.add_argument("--response-mode", choices=["auto", "legacy", "session"], default="auto")
    parser.add_argument("--no-force-key-refresh-on-miss", dest="force_key_refresh_on_miss", action="store_false")
    parser.set_defaults(force_key_refresh_on_miss=True)
    parser.add_argument("--public-key-ttl-seconds", type=int, default=600)
    parser.add_argument("--event-log", default=str(RUN_DIR / "events.jsonl"))
    parser.add_argument("--dump-dir", default=str(RUN_DIR / "dumps"))
    if include_gui_options:
        parser.add_argument("--no-autostart", action="store_true", help="Open the GUI without starting embedded mitmproxy.")
    return parser


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
