#!/usr/bin/env python3
from __future__ import annotations

import base64
import dataclasses
import gzip
import hashlib
import hmac
import json
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric import x25519

from aegis_xeapi import AegisCrypto, PublicKeyInfo, b64d, b64e, decode_key


DEFAULT_STATIC_KEY_HEX = "ab1d5a430f6bb04a3f01e81ddd72bd916d5ce591248ac128714806d7f8fb1b84"
DEFAULT_SIGN_KEY_B64 = "mUHCwVNWJbunMqAHf5MImuirT6plvs6VSFW62MGHstFQxhBGdEoIhLItH3djc4+FB/OKty3+lL2rGeoFBpVe5g=="
PC_STATIC_KEY_B64 = "hw7WBGc5HWCZzhBM50P3pDvtn/RzxDy+FW+wygIErn4="
PC_SIGN_KEY_B64 = "YN6+QFyG6D3rc3J1VT6sqwaPKE+GdwxtDweGmEPklcgrEohaE60m4Y/TtI4R/vVi17JUwwCIQF0Q2FXFmMlGrg=="
LEGACY_EAPI_RESPONSE_KEY = b"e82ckenh8dichen8"
EAPI_SEPARATOR = "-36cd479b6b5-"
# The key service has existed behind several route aliases.  Keep the
# markers independent from the transport prefix (`/api`, `/eapi`, or
# `/xeapi`) so that all of them are recognized by the MITM key flow.
KEY_PATH_MARKERS = (
    "/gorilla/anti/crawler/security/key/get",
    "/bsr/sk/get",
)
# Backwards-compatible singular name for callers that only need the original
# route marker.
KEY_PATH_MARKER = KEY_PATH_MARKERS[0]


def is_key_api_path(path: str) -> bool:
    return any(marker in path for marker in KEY_PATH_MARKERS)


def key_profile_from_os(value: Any) -> str:
    return "pc" if str(value or "").lower() in {"pc", "desktop", "windows", "mac", "osx"} else "mobile"


def key_material(profile: str) -> tuple[bytes, bytes]:
    if profile == "pc":
        return base64.b64decode(PC_STATIC_KEY_B64), PC_SIGN_KEY_B64.encode("ascii")
    return bytes.fromhex(DEFAULT_STATIC_KEY_HEX), DEFAULT_SIGN_KEY_B64.encode("ascii")


def json_loads_bytes(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"))


def json_dumps_bytes(data: Any) -> bytes:
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def maybe_b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def normalize_aes_key(key: bytes) -> bytes:
    if len(key) in (16, 24, 32):
        return key
    return hashlib.sha256(key).digest()[:16]


def parse_form_bytes(body: bytes) -> dict[str, str]:
    values = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {k: v[0] for k, v in values.items() if v}


def decrypt_eapi_params(params: str) -> str:
    cipher = bytes.fromhex(params)
    plain = AegisCrypto.aes_decrypt(LEGACY_EAPI_RESPONSE_KEY, cipher, mode=1)
    text = plain.decode("utf-8", errors="replace")
    pieces = text.split(EAPI_SEPARATOR)
    if len(pieces) >= 3:
        return pieces[1]
    return text


@dataclasses.dataclass
class EapiRequestBody:
    plain: bytes
    api_path: str
    digest: str
    digest_ok: bool | None
    envelope: str


def eapi_digest(api_path: str, payload_text: str) -> str:
    raw = f"nobody{api_path}use{payload_text}md5forencrypt".encode("utf-8")
    return hashlib.md5(raw).hexdigest()


def parse_eapi_envelope(text: str) -> EapiRequestBody:
    parts = text.split(EAPI_SEPARATOR, 2)
    if len(parts) < 3:
        return EapiRequestBody(
            plain=text.encode("utf-8", errors="replace"),
            api_path="",
            digest="",
            digest_ok=None,
            envelope=text,
        )
    api_path, payload_text, digest = parts
    expected = eapi_digest(api_path, payload_text)
    return EapiRequestBody(
        plain=payload_text.encode("utf-8", errors="replace"),
        api_path=api_path,
        digest=digest,
        digest_ok=digest.lower() == expected,
        envelope=text,
    )


def decrypt_eapi_request_body(body: bytes) -> EapiRequestBody:
    values = parse_form_bytes(body)
    params = values.get("params")
    if not params:
        raise ValueError("missing form field: params")
    cipher = bytes.fromhex(params)
    plain = AegisCrypto.aes_decrypt(LEGACY_EAPI_RESPONSE_KEY, cipher, mode=1)
    return parse_eapi_envelope(plain.decode("utf-8", errors="replace"))


def find_nonce_in_json_text(text: str) -> str | None:
    try:
        payload = json.loads(text)
    except Exception:
        return None
    if isinstance(payload, Mapping) and payload.get("nonce") is not None:
        return str(payload["nonce"])
    return None


def extract_request_nonce(body: bytes) -> str | None:
    if not body:
        return None
    try:
        form = parse_form_bytes(body)
        if "nonce" in form:
            return form["nonce"]
        if "params" in form:
            nonce = find_nonce_in_json_text(decrypt_eapi_params(form["params"]))
            if nonce:
                return nonce
        for value in form.values():
            stripped = value.strip()
            if stripped.startswith("{"):
                nonce = find_nonce_in_json_text(stripped)
                if nonce:
                    return nonce
    except Exception:
        pass
    try:
        nonce = find_nonce_in_json_text(body.decode("utf-8", errors="replace"))
        if nonce:
            return nonce
    except Exception:
        pass
    return None


def response_signature(sign_key: bytes, timestamp: str | int, request_nonce: str) -> str:
    data = f"{timestamp}{request_nonce}".encode("utf-8")
    return b64e(hmac.new(sign_key, data, hashlib.sha256).digest())


@dataclasses.dataclass
class KeyResponseBody:
    payload: Any
    encoding: str
    legacy_gzip: bool = False


def _looks_like_json(data: bytes) -> bool:
    stripped = data.lstrip()
    return stripped.startswith((b"{", b"["))


def _decrypt_legacy_eapi_response(raw: bytes) -> tuple[Any, bool]:
    plain = AegisCrypto.aes_decrypt(LEGACY_EAPI_RESPONSE_KEY, raw, mode=1)
    legacy_gzip = False
    if plain.startswith(b"\x1f\x8b"):
        plain = gzip.decompress(plain)
        legacy_gzip = True
    return json_loads_bytes(plain), legacy_gzip


@dataclasses.dataclass
class DecryptedKeyPayload:
    key_json: dict[str, Any]
    plaintext_encoding: str


def decode_key_response_body(body: bytes) -> KeyResponseBody:
    try:
        return KeyResponseBody(json_loads_bytes(body), "json")
    except Exception:
        pass

    stripped = body.strip()
    if not stripped:
        raise ValueError("empty key response body")

    attempts: list[tuple[str, bytes]] = [("legacy-eapi-raw", stripped)]
    try:
        attempts.append(("legacy-eapi-b64", b64d(stripped.decode("utf-8", errors="strict"))))
    except Exception:
        pass
    try:
        attempts.append(("legacy-eapi-hex", bytes.fromhex(stripped.decode("ascii"))))
    except Exception:
        pass

    errors: list[str] = []
    for encoding, raw in attempts:
        try:
            payload, legacy_gzip = _decrypt_legacy_eapi_response(raw)
            return KeyResponseBody(payload, encoding, legacy_gzip)
        except Exception as exc:
            errors.append(f"{encoding}: {exc}")

    preview = stripped[:32].hex()
    raise ValueError(f"unsupported key response body encoding; first32={preview}; " + "; ".join(errors))


def encode_key_response_body(payload: Any, encoding: str, *, legacy_gzip: bool = False) -> bytes:
    plain = json_dumps_bytes(payload)
    if legacy_gzip:
        plain = gzip.compress(plain)
    if encoding == "json":
        return plain
    if encoding == "legacy-eapi-raw":
        cipher = AegisCrypto.aes_encrypt(LEGACY_EAPI_RESPONSE_KEY, plain, mode=1)
        assert isinstance(cipher, bytes)
        return cipher
    if encoding in ("legacy-eapi", "legacy-eapi-b64"):
        cipher = AegisCrypto.aes_encrypt(LEGACY_EAPI_RESPONSE_KEY, plain, mode=1)
        assert isinstance(cipher, bytes)
        return b64e(cipher).encode("ascii")
    if encoding == "legacy-eapi-hex":
        cipher = AegisCrypto.aes_encrypt(LEGACY_EAPI_RESPONSE_KEY, plain, mode=1)
        assert isinstance(cipher, bytes)
        return cipher.hex().encode("ascii")
    raise ValueError(f"unsupported key response body encoding: {encoding}")


def decode_public_key_plaintext(plain: bytes) -> DecryptedKeyPayload:
    try:
        decoded = json_loads_bytes(plain)
        if isinstance(decoded, dict):
            return DecryptedKeyPayload(decoded, "json")
    except Exception:
        pass

    decoded_plain = b64d(plain.decode("utf-8", errors="strict").strip())
    decoded = json_loads_bytes(decoded_plain)
    if not isinstance(decoded, dict):
        raise ValueError("decrypted key response is not a JSON object")
    return DecryptedKeyPayload(decoded, "b64-json")


def encode_public_key_plaintext(key_json: Mapping[str, Any], encoding: str) -> bytes:
    plain = json_dumps_bytes(dict(key_json))
    if encoding == "json":
        return plain
    if encoding == "b64-json":
        return b64e(plain).encode("ascii")
    raise ValueError(f"unsupported key plaintext encoding: {encoding}")


def decrypt_key_response_payload(payload: Mapping[str, Any], static_key: bytes) -> DecryptedKeyPayload | None:
    data = payload.get("data")
    if not isinstance(data, Mapping):
        return None
    encrypted_data = data.get("encryptedData")
    if not isinstance(encrypted_data, str) or not encrypted_data:
        return None
    raw = b64d(encrypted_data)
    plain = AegisCrypto.aes_decrypt(static_key, raw, mode=1)
    return decode_public_key_plaintext(plain)


def encrypt_key_response_payload(
    key_json: Mapping[str, Any],
    static_key: bytes,
    *,
    plaintext_encoding: str = "json",
) -> str:
    plain = encode_public_key_plaintext(key_json, plaintext_encoding)
    cipher = AegisCrypto.aes_encrypt(static_key, plain, mode=1)
    assert isinstance(cipher, bytes)
    return b64e(cipher)


@dataclasses.dataclass
class KeyRewriteResult:
    payload: Any
    public_info: PublicKeyInfo
    encrypted_response: bool
    signature_ok: bool | None
    plaintext_encoding: str | None = None


def rewrite_key_response(
    payload: Any,
    *,
    proxy_public_key_b64: str,
    static_key: bytes,
    sign_key: bytes,
    request_nonce: str | None,
    ttl_seconds: int | None = None,
) -> KeyRewriteResult | None:
    if not isinstance(payload, dict):
        return None

    encrypted_response = False
    signature_ok: bool | None = None
    key_json: dict[str, Any] | None = None
    data = payload.get("data")

    if isinstance(data, Mapping) and isinstance(data.get("encryptedData"), str):
        encrypted_response = True
        decrypted = decrypt_key_response_payload(payload, static_key)
        if decrypted is None:
            return None
        key_json = decrypted.key_json
        timestamp = data.get("timestamp")
        signature = data.get("signature")
        if request_nonce and timestamp is not None and isinstance(signature, str):
            signature_ok = hmac.compare_digest(
                signature,
                response_signature(sign_key, timestamp, request_nonce),
            )
        public_info = PublicKeyInfo.from_json(key_json)
        key_json["publicKey"] = proxy_public_key_b64
        if ttl_seconds is not None and ttl_seconds > 0:
            key_json["nextUpdateTime"] = int((time.time() + ttl_seconds) * 1000)
        data["encryptedData"] = encrypt_key_response_payload(
            key_json,
            static_key,
            plaintext_encoding=decrypted.plaintext_encoding,
        )
        if request_nonce and timestamp is not None:
            data["signature"] = response_signature(sign_key, timestamp, request_nonce)
        return KeyRewriteResult(
            payload,
            public_info,
            encrypted_response,
            signature_ok,
            decrypted.plaintext_encoding,
        )

    key_data: Any = data if isinstance(data, Mapping) else payload
    if not isinstance(key_data, dict) or not key_data.get("publicKey"):
        return None
    public_info = PublicKeyInfo.from_json(key_data)
    key_data["publicKey"] = proxy_public_key_b64
    if ttl_seconds is not None and ttl_seconds > 0:
        key_data["nextUpdateTime"] = int((time.time() + ttl_seconds) * 1000)
    return KeyRewriteResult(payload, public_info, encrypted_response, signature_ok, None)


def extract_dynamic_key_from_s_plain(s_plain: bytes) -> bytes:
    first = s_plain.split(b"|", 1)[0]
    # CSR handshake stores the dynamic key as unpadded base64url; legacy BSR
    # used padded standard base64.  urlsafe_b64decode accepts both once the
    # missing padding is restored.
    first += b"=" * ((4 - len(first) % 4) % 4)
    dynamic_key = base64.urlsafe_b64decode(first)
    if len(dynamic_key) not in (16, 24, 32):
        raise ValueError(f"unexpected dynamic key length: {len(dynamic_key)}")
    return dynamic_key


def decrypt_and_rewrap_xeapi_request(
    body: bytes,
    *,
    static_key: bytes,
    proxy_private_key: x25519.X25519PrivateKey,
    real_public_info: PublicKeyInfo,
    hkdf_salt: bytes = b"",
    hkdf_info: bytes | None = None,
) -> tuple[bytes, bytes, bytes, bytes]:
    values = parse_form_bytes(body)
    # Mobile xeapi historically called the business ciphertext `B`; newer
    # clients (CSR) call the same field `C` and use base64url encoding.
    business_field = "B" if "B" in values else "C"
    missing = [name for name in (business_field, "S", "R") if name not in values]
    if missing:
        raise ValueError(f"missing form fields: {', '.join(missing)}")

    def decode_wire_value(value: str) -> bytes:
        # CSR uses unpadded base64url for C while legacy B/S/R uses regular
        # base64.  Accept both representations transparently.
        raw = value.encode("ascii")
        raw += b"=" * ((4 - len(raw) % 4) % 4)
        return base64.urlsafe_b64decode(raw)

    try:
        s_wire = decode_wire_value(values["S"])
    except Exception as exc:
        raise ValueError(f"CSR S base64 decode failed: {exc}; chars={len(values['S'])}") from exc
    try:
        c_wire = decode_wire_value(values[business_field])
    except Exception as exc:
        raise ValueError(f"CSR {business_field} base64 decode failed: {exc}; chars={len(values[business_field])}") from exc
    try:
        r_wire = decode_wire_value(values["R"])
    except Exception as exc:
        raise ValueError(f"CSR R base64 decode failed: {exc}; chars={len(values['R'])}") from exc
    try:
        s_plain = AegisCrypto.unwrap_dynamic_key_for_test(
            s_wire,
            own_private_key=proxy_private_key,
            salt=hkdf_salt,
            info=hkdf_info,
        )
    except Exception as exc:
        raise ValueError(f"CSR S unwrap failed: wire_len={len(s_wire)}; {exc}") from exc
    try:
        dynamic_key = extract_dynamic_key_from_s_plain(s_plain)
    except Exception as exc:
        raise ValueError(f"CSR dynamic key extract failed: S_plain_len={len(s_plain)}; first32={s_plain[:32].hex()}; {exc}") from exc
    try:
        b_plain = AegisCrypto.decrypt_business_data(
            c_wire,
            static_key=static_key,
            dynamic_key=dynamic_key,
        )
    except Exception as exc:
        raise ValueError(
            f"CSR {business_field} business decrypt failed: wire_len={len(c_wire)}; "
            f"dynamic_len={len(dynamic_key)}; static_len={len(static_key)}; {exc}"
        ) from exc
    try:
        r_plain = AegisCrypto.decrypt_version_info(r_wire, static_key=static_key)
    except Exception as exc:
        raise ValueError(f"CSR R decrypt failed: wire_len={len(r_wire)}; static_len={len(static_key)}; {exc}") from exc

    real_s = AegisCrypto.wrap_dynamic_key(
        s_plain,
        peer_public_key=real_public_info.public_key,
        salt=hkdf_salt,
        info=hkdf_info,
    )
    values["S"] = b64e(real_s)
    rewritten = urllib.parse.urlencode(values).encode("utf-8")
    return rewritten, dynamic_key, b_plain, r_plain


def try_decrypt_response_body(
    body: bytes | str,
    *,
    request_key: bytes | None,
    session_key: bytes | None,
    mode: str = "auto",
) -> tuple[bytes, str] | None:
    if isinstance(body, str):
        raw_body = body.strip().encode("utf-8")
        stripped_body = raw_body
    else:
        raw_body = body
        stripped_body = body.strip()
    if not raw_body:
        return None

    ciphertexts: list[tuple[str, bytes]] = []
    if len(raw_body) % 16 == 0:
        ciphertexts.append(("raw", raw_body))
    if stripped_body != raw_body and len(stripped_body) % 16 == 0:
        ciphertexts.append(("raw-stripped", stripped_body))
    try:
        ciphertexts.append(("b64", b64d(stripped_body.decode("ascii"))))
    except Exception:
        pass
    if not ciphertexts:
        return None

    attempts: list[tuple[str, bytes]] = []
    if mode in ("auto", "legacy"):
        attempts.append(("legacy-eapi", LEGACY_EAPI_RESPONSE_KEY))
    if mode in ("auto", "session"):
        if session_key:
            attempts.append(("session", normalize_aes_key(session_key)))
        if request_key:
            attempts.append(("request-dynamic", normalize_aes_key(request_key)))

    for label, key in attempts:
        for wire_label, raw in ciphertexts:
            try:
                plain = AegisCrypto.aes_decrypt(key, raw, mode=1)
                label_with_wire = f"{label}:{wire_label}"
                if plain.startswith(b"\x1f\x8b"):
                    plain = gzip.decompress(plain)
                    label_with_wire += "+gzip"
                return plain, label_with_wire
            except Exception:
                continue
    return None


def write_event(path: Path | None, event: Mapping[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"ts": time.time(), **dict(event)}
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def text_preview(data: bytes, limit: int = 4000) -> str:
    text = data.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit] + f"\n... <truncated {len(text) - limit} chars>"
    return text
