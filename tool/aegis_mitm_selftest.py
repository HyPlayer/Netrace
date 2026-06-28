#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from aegis_xeapi import (
    EAPI_SEPARATOR,
    KEY_GET_API_PATH,
    AegisConfig,
    AegisCrypto,
    AegisXeapiClient,
    PublicKeyInfo,
    b64d,
    b64e,
    decode_session_key,
    eapi_digest,
)
from tool.aegis_mitm_core import (
    decode_key_response_body,
    decode_public_key_plaintext,
    decrypt_and_rewrap_xeapi_request,
    decrypt_eapi_params,
    decrypt_eapi_request_body,
    encode_key_response_body,
    encrypt_key_response_payload,
    extract_request_nonce,
    response_signature,
    rewrite_key_response,
)
from tool.aegis_mitm_addon import load_or_create_proxy_private_key, public_bytes_for_private_key
from tool.handler_eapi import EapiHandler
from tool.handler_weapi import (
    WEAPI_SERVER_EXPONENT_HEX,
    WEAPI_SERVER_MODULUS_HEX,
    WeapiHandler,
    encrypt_weapi_params,
    rsa_encrypt_no_padding_hex,
)
from tool.handler_xeapi import XeapiHandler
from tool.mitm_context import MitmContext
from tool.protocols import ProtocolRegistry


def _key_json(public_key: bytes) -> dict[str, object]:
    return {
        "publicKey": b64e(public_key),
        "version": "1000000000000",
        "nextUpdateTime": 1803882269000,
        "sk": "selftest-sk",
    }


def main() -> None:
    static_key = bytes.fromhex("00" * 31 + "01")
    sign_key = b"mitm-selftest-sign-key"
    request_nonce = "1234567890123456"
    timestamp = "1779955023124"
    assert (
        response_signature(
            b"mUHCwVNWJbunMqAHf5MImuirT6plvs6VSFW62MGHstFQxhBGdEoIhLItH3djc4+FB/OKty3+lL2rGeoFBpVe5g==",
            "1782575848857",
            "6359567744497430",
        )
        == "d/FsukVxwzcK74wlVTuiJkmTJFP6oWY57htw7H7AZGU="
    )

    real_private = x25519.X25519PrivateKey.generate()
    real_public = real_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    proxy_private = x25519.X25519PrivateKey.generate()
    proxy_public = proxy_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    with tempfile.TemporaryDirectory() as tmp:
        proxy_key_path = Path(tmp) / "proxy-server-x25519.key"
        persisted_private = load_or_create_proxy_private_key(proxy_key_path)
        loaded_private = load_or_create_proxy_private_key(proxy_key_path)
        assert public_bytes_for_private_key(persisted_private) == public_bytes_for_private_key(loaded_private)

    original_key_json = _key_json(real_public)
    payload = {
        "code": 200,
        "data": {
            "encryptedData": encrypt_key_response_payload(
                original_key_json,
                static_key,
                plaintext_encoding="b64-json",
            ),
            "signature": response_signature(sign_key, timestamp, request_nonce),
            "timestamp": timestamp,
        },
    }

    legacy_body = encode_key_response_body(payload, "legacy-eapi")
    decoded_body = decode_key_response_body(legacy_body)
    result = rewrite_key_response(
        decoded_body.payload,
        proxy_public_key_b64=b64e(proxy_public),
        static_key=static_key,
        sign_key=sign_key,
        request_nonce=request_nonce,
    )
    assert result is not None
    assert result.public_info.public_key == real_public
    assert result.signature_ok is True
    assert result.plaintext_encoding == "b64-json"
    forged_body = encode_key_response_body(result.payload, decoded_body.encoding)
    forged_payload = decode_key_response_body(forged_body).payload
    forged_key_info = AegisCrypto.aes_decrypt(
        static_key,
        b64d(forged_payload["data"]["encryptedData"]),
        mode=1,
    )
    assert decode_public_key_plaintext(forged_key_info).key_json["publicKey"] == b64e(proxy_public)

    client = AegisXeapiClient(
        AegisConfig(static_key=static_key, sign_key=sign_key, device_id="selftest"),
        public_key_info=PublicKeyInfo.from_json(_key_json(proxy_public)),
    )
    key_request_body, key_request_nonce = client.build_public_key_request_body(
        active=False,
        timestamp=timestamp,
        nonce=request_nonce,
    )
    assert key_request_nonce == request_nonce
    key_request_params = urllib.parse.parse_qs(key_request_body.decode("utf-8"))["params"][0]
    key_request_plain = AegisCrypto.aes_decrypt(
        b"e82ckenh8dichen8",
        bytes.fromhex(key_request_params),
        mode=1,
    ).decode("utf-8")
    key_api_path, key_payload_text, key_digest = key_request_plain.split(EAPI_SEPARATOR)
    assert key_api_path == KEY_GET_API_PATH
    assert key_digest == eapi_digest(KEY_GET_API_PATH, key_payload_text)
    key_payload = json.loads(key_payload_text)
    assert key_payload["currentKeyVersion"] == "1000000000000"
    assert key_payload["requestType"] == "passive"
    assert key_payload["signature"] == response_signature(sign_key, timestamp, request_nonce)

    key_response_payload = {
        "code": 200,
        "data": {
            "encryptedData": encrypt_key_response_payload(
                original_key_json,
                static_key,
                plaintext_encoding="json",
            ),
            "signature": response_signature(sign_key, timestamp, request_nonce),
            "timestamp": timestamp,
        },
    }
    key_response_plain = json.dumps(key_response_payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    key_response_cipher = AegisCrypto.aes_encrypt(b"e82ckenh8dichen8", key_response_plain, mode=1)
    assert isinstance(key_response_cipher, bytes)
    decoded_key_info = client.decode_public_key_response_body(
        key_response_cipher,
        request_nonce=request_nonce,
    )
    assert decoded_key_info.public_key == real_public

    request_plain = {"uri": "/api/selftest", "body": b64e(b"hello")}
    proxy_body = client.encrypt_xeapi_body(request_plain).encode("utf-8")
    rewritten, dynamic_key, plain, r_plain = decrypt_and_rewrap_xeapi_request(
        proxy_body,
        static_key=static_key,
        proxy_private_key=proxy_private,
        real_public_info=PublicKeyInfo.from_json(original_key_json),
    )
    assert json.loads(plain.decode("utf-8")) == request_plain
    assert r_plain == b"1000000000000|"

    values = urllib.parse.parse_qs(rewritten.decode("utf-8"))
    real_s_plain = AegisCrypto.unwrap_dynamic_key_for_test(
        b64d(values["S"][0]),
        own_private_key=real_private,
    )
    assert real_s_plain.startswith(b64e(dynamic_key).encode("ascii"))

    session_id = "f5af34cd95e64d48a33dd00f01f03384"
    session_key_text = "44866835ed63479da39e05d2733a7121"
    assert decode_session_key(session_key_text) == session_key_text.encode("utf-8")
    client.handle_response_headers({"x-encr-ssid": session_id, "x-encr-sskey": session_key_text})
    session_body = client.encrypt_xeapi_body(request_plain).encode("utf-8")
    session_values = urllib.parse.parse_qs(session_body.decode("utf-8"))
    session_s_plain = AegisCrypto.unwrap_dynamic_key_for_test(
        b64d(session_values["S"][0]),
        own_private_key=proxy_private,
    )
    assert session_s_plain.startswith(b64e(session_key_text.encode("utf-8")).encode("ascii"))
    assert (
        AegisCrypto.decrypt_version_info(b64d(session_values["R"][0]), static_key=static_key)
        == f"1000000000000|{session_id}".encode("utf-8")
    )
    assert json.loads(
        AegisCrypto.decrypt_business_data(
            b64d(session_values["B"][0]),
            static_key=static_key,
            dynamic_key=session_key_text.encode("utf-8"),
        ).decode("utf-8")
    ) == request_plain

    eapi_params = urllib.parse.urlencode({"params": _serial_eapi_params("/api/selftest", {"nonce": request_nonce})})
    assert extract_request_nonce(eapi_params.encode("utf-8")) == request_nonce
    assert json.loads(decrypt_eapi_params(urllib.parse.parse_qs(eapi_params)["params"][0]))["nonce"] == request_nonce
    eapi_body = decrypt_eapi_request_body(eapi_params.encode("utf-8"))
    assert eapi_body.api_path == "/api/selftest"
    assert eapi_body.digest_ok is True
    assert json.loads(eapi_body.plain.decode("utf-8"))["nonce"] == request_nonce
    _test_protocol_registry(eapi_params.encode("utf-8"))
    print("aegis mitm selftest ok")


def _serial_eapi_params(api_path: str, payload: dict[str, str]) -> str:
    import hashlib

    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.md5(f"nobody{api_path}use{text}md5forencrypt".encode("utf-8")).hexdigest()
    plain = f"{api_path}-36cd479b6b5-{text}-36cd479b6b5-{digest}".encode("utf-8")
    cipher = AegisCrypto.aes_encrypt(b"e82ckenh8dichen8", plain, mode=1)
    assert isinstance(cipher, bytes)
    return cipher.hex().upper()


def _test_protocol_registry(key_body: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        ctx = MitmContext()
        ctx.event_log = Path(tmp) / "events.jsonl"
        registry = ProtocolRegistry([XeapiHandler(), EapiHandler(), WeapiHandler()])

        key_flow = _FakeFlow(
            "POST",
            "https://interface3.music.163.com/eapi/gorilla/anti/crawler/security/key/get",
            "/eapi/gorilla/anti/crawler/security/key/get",
            {"content-type": "application/x-www-form-urlencoded"},
            key_body,
        )
        assert registry.key_handler_for(key_flow, ctx).name == "xeapi"
        assert registry.request_handler_for(key_flow).name == "eapi"

        miss_flow = _FakeFlow("GET", "https://example.com/plain", "/plain", {}, b"")
        assert registry.key_handler_for(miss_flow, ctx) is None
        assert registry.request_handler_for(miss_flow) is None
        assert miss_flow.request.content == b""
        assert miss_flow.metadata == {}

        weapi_flow = _FakeFlow(
            "POST",
            "https://music.163.com/weapi/test",
            "/weapi/test",
            {"content-type": "application/x-www-form-urlencoded"},
            b"params=abc",
        )
        weapi = registry.request_handler_for(weapi_flow)
        assert weapi is not None
        assert weapi.name == "weapi"
        before = weapi_flow.request.content
        weapi.handle_request(weapi_flow, ctx)
        assert weapi_flow.request.content == before
        assert weapi_flow.metadata["netrace_protocol"] == "weapi"
        event = json.loads(ctx.event_log.read_text(encoding="utf-8").splitlines()[-1])
        assert event["protocol"] == "weapi"
        assert event["operation"] == "decrypt-failed"
        assert event["status"] == "weapi: missing params or encSecKey"

        js_flow = _FakeFlow(
            "GET",
            "https://webcache.music.163.net/web/s/core_abcd1234.js",
            "/web/s/core_abcd1234.js",
            {},
            b"",
        )
        js_flow.response = _FakeResponse(
            b'var b="010001",c="00e0b509";var k=new RSAKeyPair(b,"",c);',
            {"content-type": "application/javascript"},
        )
        assert registry.key_handler_for(js_flow, ctx).name == "weapi"
        weapi.handle_key_response(js_flow, ctx)
        rewritten_js = js_flow.response.content.decode("utf-8")
        assert 'new RSAKeyPair("' in rewritten_js
        assert "new RSAKeyPair(b" not in rewritten_js

        aes_key = b"0123456789ABCDEF"
        params = encrypt_weapi_params(b'{"hello":"weapi"}', aes_key)
        enc_sec_key = _rsa_encrypt_no_padding(aes_key[::-1], ctx.weapi_private_key)
        decrypt_flow = _FakeFlow(
            "POST",
            "https://music.163.com/weapi/test",
            "/weapi/test",
            {"content-type": "application/x-www-form-urlencoded"},
            urllib.parse.urlencode({"params": params, "encSecKey": enc_sec_key}).encode("utf-8"),
        )
        weapi.handle_request(decrypt_flow, ctx)
        event = json.loads(ctx.event_log.read_text(encoding="utf-8").splitlines()[-1])
        assert event["protocol"] == "weapi"
        assert event["status"] == "weapi-decrypted"
        assert json.loads(event["detail"]) == {"hello": "weapi"}
        rewritten_form = urllib.parse.parse_qs(decrypt_flow.request.content.decode("utf-8"))
        assert rewritten_form["params"][0] == params
        assert rewritten_form["encSecKey"][0] == rsa_encrypt_no_padding_hex(
            aes_key[::-1],
            WEAPI_SERVER_EXPONENT_HEX,
            WEAPI_SERVER_MODULUS_HEX,
        )


class _FakeHeaders(dict[str, str]):
    def get(self, key: str, default=None):  # type: ignore[no-untyped-def]
        for name, value in self.items():
            if name.lower() == key.lower():
                return value
        return default


class _FakeRequest:
    def __init__(self, method: str, url: str, path: str, headers: dict[str, str], content: bytes) -> None:
        self.method = method
        self.pretty_url = url
        self.path = path
        self.headers = _FakeHeaders(headers)
        self.content = content


class _FakeFlow:
    def __init__(self, method: str, url: str, path: str, headers: dict[str, str], content: bytes) -> None:
        self.id = f"fake:{path}"
        self.request = _FakeRequest(method, url, path, headers, content)
        self.response = None
        self.metadata: dict[str, str] = {}


class _FakeResponse:
    def __init__(self, content: bytes, headers: dict[str, str] | None = None, status_code: int = 200) -> None:
        self.content = content
        self.headers = _FakeHeaders(headers or {})
        self.status_code = status_code


def _rsa_encrypt_no_padding(plain: bytes, private_key) -> str:  # type: ignore[no-untyped-def]
    numbers = private_key.private_numbers().public_numbers
    encrypted = pow(int.from_bytes(plain, "big"), numbers.e, numbers.n)
    return encrypted.to_bytes(private_key.key_size // 8, "big").hex()




if __name__ == "__main__":
    main()
