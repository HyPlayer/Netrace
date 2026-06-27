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

from aegis_xeapi import AegisConfig, AegisCrypto, AegisXeapiClient, PublicKeyInfo, b64d, b64e
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

    eapi_params = urllib.parse.urlencode({"params": _serial_eapi_params("/api/selftest", {"nonce": request_nonce})})
    assert extract_request_nonce(eapi_params.encode("utf-8")) == request_nonce
    assert json.loads(decrypt_eapi_params(urllib.parse.parse_qs(eapi_params)["params"][0]))["nonce"] == request_nonce
    eapi_body = decrypt_eapi_request_body(eapi_params.encode("utf-8"))
    assert eapi_body.api_path == "/api/selftest"
    assert eapi_body.digest_ok is True
    assert json.loads(eapi_body.plain.decode("utf-8"))["nonce"] == request_nonce
    print("aegis mitm selftest ok")


def _serial_eapi_params(api_path: str, payload: dict[str, str]) -> str:
    import hashlib

    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.md5(f"nobody{api_path}use{text}md5forencrypt".encode("utf-8")).hexdigest()
    plain = f"{api_path}-36cd479b6b5-{text}-36cd479b6b5-{digest}".encode("utf-8")
    cipher = AegisCrypto.aes_encrypt(b"e82ckenh8dichen8", plain, mode=1)
    assert isinstance(cipher, bytes)
    return cipher.hex().upper()


if __name__ == "__main__":
    main()
