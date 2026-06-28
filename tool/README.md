# Netrace TUI

Textual-based helper for driving Netrace, an embedded mitmproxy TUI for active
MITM against the Aegis `/xeapi` flow, observing traditional `/eapi` traffic,
and adding future protocol handlers during local reverse-engineering.

The addon replaces the public key returned by
`/gorilla/anti/crawler/security/key/get` with a local X25519 key. That lets the
proxy unwrap `S`, decrypt `B`, show the plaintext request, then rewrap the same
`S` plaintext with the real server public key before forwarding the request.

For `/eapi`, the addon decrypts the form `params` envelope with the legacy eapi
key, verifies the MD5 envelope, shows the plaintext request, and attempts to
decrypt the response with the same legacy response key. `/eapi` requests are not
rewritten.

For `/weapi`, the handler rewrites the RSA public key in web core JavaScript,
decrypts request `encSecKey` with the local RSA private key, then decrypts the
double AES-CBC `params` payload. It re-encrypts `encSecKey` with the original
web RSA public key before forwarding to the server. Responses are treated as
plaintext passthrough.

## Install

```powershell
uv sync
```

## Run

```powershell
uv run netrace --listen-host 0.0.0.0 --listen-port 8080
```

Configure the Android device or emulator to use the mitmproxy listener as its
HTTP(S) proxy and install/trust the mitmproxy CA certificate.

## Files

```text
tool/aegis_tui.py        Textual UI and embedded mitmproxy launcher
tool/aegis_mitm_addon.py Thin mitmproxy dispatch addon
tool/mitm_context.py     Shared state, dumps, and JSONL events
tool/protocols.py        Protocol handler interface and registry
tool/handler_xeapi.py    /xeapi key hijack and decrypt/rewrite handler
tool/handler_eapi.py     /eapi decrypt-only observer
tool/handler_weapi.py    /weapi core JS key rewrite and request decrypt handler
tool/key_hijack.py       Reusable public-key response rewrite helper
tool/aegis_mitm_core.py  Shared crypto / rewrite helpers
tool/aegis_mitm_selftest.py Offline self-test for the rewrite/decrypt chain
tool/runs/events.jsonl  Runtime event stream consumed by the TUI
tool/runs/dumps/        Decrypted request/response dumps
```

## Options

```powershell
python .\tool\aegis_tui.py `
  --static-key hex:ab1d5a430f6bb04a3f01e81ddd72bd916d5ce591248ac128714806d7f8fb1b84 `
  --sign-key b64:mUHCwVNWJbunMqAHf5MImuirT6plvs6VSFW62MGHstFQxhBGdEoIhLItH3djc4+FB/OKty3+lL2rGeoFBpVe5g== `
  --response-mode auto
```

To use a trusted custom CA for transparent MITM, point the tool at a mitmproxy
confdir or a CA PEM file:

```powershell
python .\tool\aegis_tui.py --confdir E:\mitm\conf
python .\tool\aegis_tui.py --ca-pem E:\mitm\mitmproxy-ca.pem
```

By default, the TUI loads `tool/capture-ca.pem` if it exists. The file must
contain both the trusted CA certificate and its private key, in PEM format.

By default, embedded mitmproxy runs through the upstream proxy
`http://127.0.0.1:9370`. Override it with `--upstream-proxy`; explicit
`socks5://...` values are bridged locally when needed.

Upstream TLS verification is disabled by default (`--ssl-insecure`) so the
proxy can sit behind another intercepting proxy. Use `--ssl-verify-upstream` to
turn verification back on.

If `/xeapi` traffic appears before the app calls `key/get`, the addon injects
`x-ud-sts=10000` once to ask the client to refresh its Aegis public key. Disable
that with `--no-force-key-refresh-on-miss`.

Rewritten public-key responses set `nextUpdateTime` to 10 minutes from rewrite
time by default. Override with `--public-key-ttl-seconds`.

`--response-mode` can be:

```text
auto     try legacy eapi response key, then session/request keys
legacy   only try AES-128-ECB key e82ckenh8dichen8
session  only try active session/request dynamic keys
```

## Self-Test

Run the offline chain test before a live session:

```powershell
python .\tool\aegis_mitm_selftest.py
```

It verifies:

```text
legacy eapi key/get response decode/re-encode
data.encryptedData JSON and Base64(JSON) plaintext handling
signature recomputation using the captured request nonce
proxy public-key substitution
/xeapi request B/S/R decrypt and S rewrap to the real public key
legacy eapi params nonce extraction
```

Expected output:

```text
aegis mitm selftest ok
```

## Current Limits

The key replacement path supports plain public-key JSON responses, native
`data.encryptedData/signature/timestamp` responses, legacy eapi response bodies,
and both JSON and Base64(JSON) public-key plaintexts after static AES decrypt.

The Java plaintext envelope builder is still represented by whatever the app
sends into native; this tool observes and decrypts it, but does not yet
synthesize Java requests from scratch.

When a request or response decrypts successfully, the TUI event includes a
preview and the addon writes the full plaintext into `tool/runs/dumps/`.
