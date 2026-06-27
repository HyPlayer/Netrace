# Python Aegis /xeapi Reimplementation

Main file:

```text
aegis_xeapi.py
```

## Goal

This is a Python-side reimplementation of the Aegis native `/xeapi` flow, not the legacy `/eapi params` flow.

Implemented:

```text
AES mode 0: CBC + PKCS#7
AES mode 1: ECB + PKCS#7
AES mode 2: GCM with 12-byte IV and 16-byte tag
Business body B
Dynamic-key wrapper S
Version block R, currently configurable
Cold-start public-key fetch through /eapi/gorilla/anti/crawler/security/key/get
Public-key response decrypt + signature verification
Response header handling for session/public-key update
Offline decrypt helpers when the dynamic/session key is known
```

## Known Native Constants

`REFERENCE.md` and decoded app strings identify these Android 9.5.15 constants.
The sign algorithm and static AES usage have been confirmed in native; the
literal Java decoded blobs should still be checked against the target APK build
when version fidelity matters.

```text
static AES key:
ab1d5a430f6bb04a3f01e81ddd72bd916d5ce591248ac128714806d7f8fb1b84

sign key:
mUHCwVNWJbunMqAHf5MImuirT6plvs6VSFW62MGHstFQxhBGdEoIhLItH3djc4+FB/OKty3+lL2rGeoFBpVe5g==

legacy eapi response key:
e82ckenh8dichen8
```

## From Empty State To Communication

The client-side flow is:

```text
1. Configure static key, sign key, device id, app fields.
2. Fetch public key from gorilla/anti/crawler/security/key/get.
3. Generate a local dynamic key.
4. Build plaintext JSON for the target /xeapi API.
5. Generate form body:
   B=<business ciphertext>&S=<wrapped dynamic key>&R=<version info>
6. POST to /xeapi/... with:
   X-Client-Enc-State: ENCRYPTED
   Content-Type: application/x-www-form-urlencoded
7. Read response headers:
   x-encr-ssid / x-encr-sskey -> set session
   x-ud-sts=10000 or 20002 -> refresh public key
   x-ud-sts=8888 -> global decrypt fallback
8. Continue later requests with the session key when present.
```

## Important Boundary

`S` is intentionally asymmetric:

```text
client dynamic key -> X25519 + HKDF + AES-GCM -> S
```

For a live request, only the server has the private key needed to unwrap `S`. Therefore an offline HAR alone cannot reveal the dynamic key. To decrypt offline request/response payloads, capture the active dynamic/session key from the running client or native process.

## CLI

Self-test:

```powershell
python aegis_xeapi.py selftest
```

Encrypt a payload:

```powershell
python aegis_xeapi.py encrypt `
  --static-key hex:00112233445566778899aabbccddeeff `
  --sign-key hex:00112233445566778899aabbccddeeff `
  --device-id demo-device `
  --public-key-json public_key.json `
  --payload '{"hello":"world"}'
```

When calibrating against native traces, override the metadata appended to `S`
or the session suffix encrypted into `R` without changing code:

```powershell
python aegis_xeapi.py encrypt `
  --static-key hex:00112233445566778899aabbccddeeff `
  --public-key-json public_key.json `
  --wrap-suffix "native-wrap-metadata" `
  --version-suffix "native-version-metadata" `
  --payload '{"hello":"world"}'
```

Decrypt form body when the dynamic/session key is known:

```powershell
python aegis_xeapi.py decrypt-form `
  --static-key hex:00112233445566778899aabbccddeeff `
  --dynamic-key hex:00112233445566778899aabbccddeeff `
  --form-body 'B=...&S=...&R=...'
```

Decrypt response body when the dynamic/session key is known:

```powershell
python aegis_xeapi.py decrypt-response `
  --static-key hex:00112233445566778899aabbccddeeff `
  --key hex:00112233445566778899aabbccddeeff `
  --body 'base64-response-body'
```

## Python API

```python
from aegis_xeapi import AegisConfig, AegisXeapiClient, PublicKeyInfo

config = AegisConfig(
    static_key=bytes.fromhex("00112233445566778899aabbccddeeff"),
    sign_key=bytes.fromhex("00112233445566778899aabbccddeeff"),
    device_id="device-id",
    app_version="...",
    uid=0,
)

client = AegisXeapiClient(config)
client.bootstrap(headers={...})

resp = client.post_xeapi(
    "https://interface3.music.163.com/xeapi/...",
    {"foo": "bar"},
    headers={...},
)
```

## Public Key JSON

Expected file shape:

```json
{
  "publicKey": "base64-raw-x25519-public-key",
  "version": "1",
  "sk": "server-key-metadata",
  "nextUpdateTime": 0
}
```

The live key endpoint may wrap this under a `data` object. The Python loader accepts both direct endpoint JSON and direct file JSON.
The loader also preserves the raw public-key JSON and accepts common version aliases such as `keyVersion` and `currentKeyVersion`.

Native key refresh requests are sent as standard eapi form data:

```text
POST /eapi/gorilla/anti/crawler/security/key/get
Content-Type: application/x-www-form-urlencoded

params=<AES-ECB-hex eapi serialdata>
```

The decrypted eapi plaintext is:

```text
/api/gorilla/anti/crawler/security/key/get
-36cd479b6b5-
{"appVersion":"...","currentKeyVersion":"...","deviceId":"...","nonce":"...","signature":"..."}
-36cd479b6b5-
md5
```

Native key refresh responses are not just the plain key JSON. The native
`onNetworkResponse` path expects:

```text
data.encryptedData
data.signature
data.timestamp
```

It verifies:

```text
signature == base64(HMAC-SHA256(signKey, str(data.timestamp) || requestNonce))
```

Then it base64-decodes and AES-ECB decrypts `encryptedData` using the static
key to recover the public-key JSON shown above.

## Reverse-Engineering Notes

`B`:

```text
staticCipher = AES_mode1(staticKey, plaintext)
transformed = random16 || rotate(base64(staticCipher xor random16))
B = AES_mode1(dynamicOrSessionKey, transformed)
```

`S`:

```text
wrapPlain = base64(dynamicKey) || "|" || os || "|" || sk
shared = X25519(ephemeralPrivate, serverPublicKey)
wrapKey = HKDF-SHA256(shared, salt=zero32, info=ephemeralPublic32)
S = ephemeralPublic32 || iv12 || AES-GCM(wrapKey, wrapPlain) || tag16
```

`R`:

```text
R = AES_mode1(staticKey, version || "|" || sessionId)
```

For the first request without a server session, `sessionId` is the empty string.
After response headers provide `x-encr-ssid` and `x-encr-sskey`, native uses the
ASCII bytes of `x-encr-sskey` as the dynamic/session AES key and uses
`x-encr-ssid` in `R`.

Current Python status:

```text
S/R defaults now follow the native formulas. The CLI override knobs remain
available for byte-for-byte calibration.
```

## Request Envelope Gap

The current Python API can encrypt arbitrary bytes/JSON, but the app does not
usually pass raw business params directly to native. Java first builds an
envelope similar to:

```json
{
  "method": "GET",
  "contentType": "application/json",
  "queryString": "id=123&e_r=true",
  "body": "Base64(raw body)"
}
```

Observed rules from the reference analysis:

```text
/eapi/ is normalized to /api/ inside the envelope
/api/ is rewritten to /xeapi/ for the outgoing URL
body is Android Base64.NO_WRAP of raw request body bytes
method is included when the original method is not POST
contentType is included when the body is not application/x-www-form-urlencoded
queryString is included when present
e_r=true is injected for encryption reporting when absent
```

Exact JSON byte order follows Java's `JSONObject.toString()` behavior, so
runtime plaintext capture is still the best byte-for-byte oracle.

## Response Decryption Gap

The current helper decrypts response bodies with the dynamic/session key. The
reference analysis reports that observed `/xeapi` business responses may still
use the legacy eapi response key:

```text
AES-128-ECB key: e82ckenh8dichen8
optional gzip after decrypt
```

Both response modes should remain supported until validated per endpoint.

Open calibration points:

```text
1. Implement Java-style xeapi request envelope construction.
2. Validate response decrypt mode per endpoint: legacy eapi key vs session/dynamic key.
3. Capture more dynamic/session key samples to validate B/S/R across app states.
```
