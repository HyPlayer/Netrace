#!/usr/bin/env python3
"""
Python reimplementation scaffold for NetEase Aegis /xeapi encryption.

This file intentionally covers the whole client-side flow:

1. Keep local Aegis state: static key, sign key, dynamic key, public key info,
   and optional session key.
2. Fetch/update public key through the Java-side key endpoint shape.
3. Encrypt /xeapi request bodies as B/S/R form fields.
4. Handle response headers that update session key or trigger public-key refresh.
5. Decrypt B/R when the caller has the dynamic/session key. S can only be
   decrypted with the matching private key, which a normal client never has for
   server-generated public keys.

The native code path uses OpenSSL AES modes selected by mode + key length:

mode 0: AES-CBC, PKCS#7 padding, IV required (zero IV fallback implemented)
mode 1: AES-ECB, PKCS#7 padding
mode 2: AES-GCM, 12-byte IV, 16-byte tag

The exact packing of S/R metadata is configurable because it depends on the
server public-key JSON fields. The defaults match the current reverse-engineered
shape and HAR length constraints, but keep the knobs visible instead of hiding
magic in the implementation.
"""

from __future__ import annotations

import base64
import argparse
import dataclasses
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from typing import Any, Callable, Mapping, MutableMapping

import requests
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ANDROID_B64_NO_WRAP = "android-base64-no-wrap"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def _to_bytes(value: str | bytes, encoding: str = "utf-8") -> bytes:
    return value if isinstance(value, bytes) else value.encode(encoding)


def pkcs7_pad(data: bytes, block_bits: int = 128) -> bytes:
    padder = padding.PKCS7(block_bits).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes, block_bits: int = 128) -> bytes:
    unpadder = padding.PKCS7(block_bits).unpadder()
    return unpadder.update(data) + unpadder.finalize()


class AegisCrypto:
    """Low-level crypto primitives mirroring the native AESCipher/ECCCipher."""

    @staticmethod
    def aes_encrypt(
        key: bytes,
        plaintext: bytes,
        *,
        mode: int,
        iv: bytes | None = None,
        aad: bytes | None = None,
    ) -> bytes | tuple[bytes, bytes]:
        AegisCrypto._check_aes_key(key)
        if mode == 0:
            iv = iv or (b"\x00" * 16)
            if len(iv) != 16:
                raise ValueError("AES-CBC mode requires a 16-byte IV")
            encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
            return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
        if mode == 1:
            encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            return encryptor.update(pkcs7_pad(plaintext)) + encryptor.finalize()
        if mode == 2:
            iv = iv or os.urandom(12)
            if len(iv) != 12:
                raise ValueError("AES-GCM mode requires a 12-byte IV")
            out = AESGCM(key).encrypt(iv, plaintext, aad)
            return out[:-16], out[-16:]
        raise ValueError(f"unsupported AES mode: {mode}")

    @staticmethod
    def aes_decrypt(
        key: bytes,
        ciphertext: bytes,
        *,
        mode: int,
        iv: bytes | None = None,
        tag: bytes | None = None,
        aad: bytes | None = None,
    ) -> bytes:
        AegisCrypto._check_aes_key(key)
        if mode == 0:
            iv = iv or (b"\x00" * 16)
            decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            return pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize())
        if mode == 1:
            decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            return pkcs7_unpad(decryptor.update(ciphertext) + decryptor.finalize())
        if mode == 2:
            if iv is None or tag is None:
                raise ValueError("AES-GCM decrypt requires iv and tag")
            return AESGCM(key).decrypt(iv, ciphertext + tag, aad)
        raise ValueError(f"unsupported AES mode: {mode}")

    @staticmethod
    def transform_static_cipher(static_cipher: bytes, *, rand16: bytes | None = None) -> bytes:
        """
        Implements sub_52f4c4 as currently understood:

        random16 || rotate_left(base64(static_cipher XOR random16), random16[0] & 0xf)
        """

        rand16 = rand16 or os.urandom(16)
        if len(rand16) != 16:
            raise ValueError("rand16 must be 16 bytes")
        mixed = bytes(b ^ rand16[i & 0x0F] for i, b in enumerate(static_cipher))
        encoded = base64.b64encode(mixed)
        if encoded:
            offset = (rand16[0] & 0x0F) % len(encoded)
            encoded = encoded[offset:] + encoded[:offset]
        return rand16 + encoded

    @staticmethod
    def untransform_static_cipher(transformed: bytes) -> bytes:
        if len(transformed) < 16:
            raise ValueError("transformed static cipher is too short")
        rand16 = transformed[:16]
        encoded = transformed[16:]
        if encoded:
            offset = (rand16[0] & 0x0F) % len(encoded)
            encoded = encoded[-offset:] + encoded[:-offset] if offset else encoded
        mixed = base64.b64decode(encoded)
        return bytes(b ^ rand16[i & 0x0F] for i, b in enumerate(mixed))

    @staticmethod
    def encrypt_business_data(plaintext: bytes, *, static_key: bytes, dynamic_key: bytes) -> bytes:
        static_cipher = AegisCrypto.aes_encrypt(static_key, plaintext, mode=1)
        assert isinstance(static_cipher, bytes)
        transformed = AegisCrypto.transform_static_cipher(static_cipher)
        dynamic_cipher = AegisCrypto.aes_encrypt(dynamic_key, transformed, mode=1)
        assert isinstance(dynamic_cipher, bytes)
        return dynamic_cipher

    @staticmethod
    def decrypt_business_data(cipher_b: bytes, *, static_key: bytes, dynamic_key: bytes) -> bytes:
        transformed = AegisCrypto.aes_decrypt(dynamic_key, cipher_b, mode=1)
        static_cipher = AegisCrypto.untransform_static_cipher(transformed)
        return AegisCrypto.aes_decrypt(static_key, static_cipher, mode=1)

    @staticmethod
    def wrap_dynamic_key(
        wrap_plaintext: bytes,
        *,
        peer_public_key: bytes,
        salt: bytes = b"",
        info: bytes | None = None,
        ephemeral_private_key: x25519.X25519PrivateKey | None = None,
    ) -> bytes:
        if len(peer_public_key) != 32:
            raise ValueError("Aegis X25519 peer public key must be 32 raw bytes")
        ephemeral_private_key = ephemeral_private_key or x25519.X25519PrivateKey.generate()
        peer = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        public = ephemeral_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = ephemeral_private_key.exchange(peer)
        wrap_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt or None,
            info=public if info is None else info,
        ).derive(shared)
        iv = os.urandom(12)
        cipher, tag = AegisCrypto.aes_encrypt(wrap_key, wrap_plaintext, mode=2, iv=iv)
        assert isinstance(cipher, bytes)
        return public + iv + cipher + tag

    @staticmethod
    def unwrap_dynamic_key_for_test(
        cipher_s: bytes,
        *,
        own_private_key: x25519.X25519PrivateKey,
        salt: bytes = b"",
        info: bytes | None = None,
    ) -> bytes:
        if len(cipher_s) < 32 + 12 + 16:
            raise ValueError("cipherS is too short")
        ephemeral_public_bytes = cipher_s[:32]
        ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
        iv = cipher_s[32:44]
        tag = cipher_s[-16:]
        ciphertext = cipher_s[44:-16]
        shared = own_private_key.exchange(ephemeral_public)
        wrap_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt or None,
            info=ephemeral_public_bytes if info is None else info,
        ).derive(shared)
        return AegisCrypto.aes_decrypt(wrap_key, ciphertext, mode=2, iv=iv, tag=tag)

    @staticmethod
    def encrypt_version_info(plaintext: bytes, *, static_key: bytes) -> bytes:
        cipher = AegisCrypto.aes_encrypt(static_key, plaintext, mode=1)
        assert isinstance(cipher, bytes)
        return cipher

    @staticmethod
    def decrypt_version_info(cipher_r: bytes, *, static_key: bytes) -> bytes:
        return AegisCrypto.aes_decrypt(static_key, cipher_r, mode=1)

    @staticmethod
    def _check_aes_key(key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError(f"AES key must be 16/24/32 bytes, got {len(key)}")


@dataclasses.dataclass
class PublicKeyInfo:
    public_key: bytes
    version: str
    sk: str = ""
    next_update_time: int | None = None
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)
    wrap_suffix: str | None = None
    version_suffix: str | None = None

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "PublicKeyInfo":
        if "data" in data and isinstance(data["data"], Mapping):
            data = data["data"]
        public_key = data.get("publicKey") or data.get("public_key")
        if not public_key:
            raise ValueError("public key JSON is missing publicKey")
        if isinstance(public_key, str):
            public_key_bytes = b64d(public_key)
        else:
            public_key_bytes = bytes(public_key)
        if len(public_key_bytes) != 32:
            raise ValueError(f"Aegis public key must decode to 32 bytes, got {len(public_key_bytes)}")
        return cls(
            public_key=public_key_bytes,
            version=str(data.get("version") or data.get("keyVersion") or data.get("currentKeyVersion") or ""),
            sk=str(data.get("sk", "")),
            next_update_time=int(data["nextUpdateTime"]) if data.get("nextUpdateTime") is not None else None,
            raw=dict(data),
        )

    def wrap_metadata(self) -> str:
        if self.wrap_suffix is not None:
            return self.wrap_suffix
        return self._first_text("sk", "keyInfo", "key_info", "keyMetadata", "key_meta")

    def version_metadata(self) -> str:
        if self.version_suffix is not None:
            return self.version_suffix
        return self._first_text("sk", "keyInfo", "key_info", "keyMetadata", "key_meta")

    def _first_text(self, *names: str) -> str:
        for name in names:
            value = self.raw.get(name)
            if value is not None:
                return str(value)
        return self.sk


@dataclasses.dataclass
class AegisConfig:
    static_key: bytes
    sign_key: bytes
    device_id: str
    os_name: str = "android"
    app_version: str = ""
    uid: int = 0
    t1: str = ""
    t2: str = ""
    key_endpoint: str = "https://interface3.music.163.com/gorilla/anti/crawler/security/key/get"
    update_interval_seconds: int = 300
    hkdf_salt: bytes = b""
    hkdf_info: bytes | None = None


class AegisXeapiClient:
    def __init__(
        self,
        config: AegisConfig,
        *,
        public_key_info: PublicKeyInfo | None = None,
        session: requests.Session | None = None,
        key_request_signer: Callable[[bytes, str, str], str] | None = None,
        wrap_plaintext_builder: Callable[[bytes, PublicKeyInfo], bytes] | None = None,
        version_plaintext_builder: Callable[[PublicKeyInfo], bytes] | None = None,
    ) -> None:
        self.config = config
        self.session = session or requests.Session()
        self.public_key_info = public_key_info
        self.dynamic_key = os.urandom(16)
        self.dynamic_key_time = time.time()
        self.session_id: str | None = None
        self.session_key: bytes | None = None
        self.key_request_signer = key_request_signer or self.default_key_request_signer
        self.wrap_plaintext_builder = wrap_plaintext_builder or (
            lambda dynamic_key, info: self.default_wrap_plaintext(dynamic_key, info, self.config.os_name)
        )
        self.version_plaintext_builder = version_plaintext_builder or (
            lambda info: self.default_version_plaintext(info, self.session_id or "")
        )

    def bootstrap(self, headers: Mapping[str, str] | None = None) -> PublicKeyInfo:
        """Cold-start path: fetch public key before the first /xeapi request."""

        self.public_key_info = self.fetch_public_key(active=True, headers=headers)
        return self.public_key_info

    def fetch_public_key(
        self,
        *,
        active: bool,
        headers: Mapping[str, str] | None = None,
    ) -> PublicKeyInfo:
        timestamp = str(int(time.time() * 1000))
        nonce = "".join(str(int.from_bytes(os.urandom(4), "little") % 10) for _ in range(16))
        signature = self.key_request_signer(self.config.sign_key, timestamp, nonce)
        body = {
            "currentKeyVersion": self.public_key_info.version if self.public_key_info else "",
            "signature": signature,
            "timestamp": timestamp,
            "nonce": nonce,
            "requestType": "active" if active else "passive",
            "t1": self.config.t1,
            "t2": self.config.t2,
            "os": self.config.os_name,
            "appVersion": self.config.app_version,
            "deviceId": self.config.device_id,
            "uid": self.config.uid,
        }
        response = self.session.post(
            self.config.key_endpoint,
            json=body,
            headers=dict(headers or {}),
            timeout=15,
        )
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, Mapping) and "data" in payload and isinstance(payload["data"], Mapping):
            payload = payload["data"]
        return PublicKeyInfo.from_json(payload)

    def encrypt_xeapi_body(self, payload: Mapping[str, Any] | str | bytes) -> str:
        """Return an application/x-www-form-urlencoded body with B/S/R."""

        if self.public_key_info is None:
            raise RuntimeError("public_key_info is missing; call bootstrap() or pass it to the constructor")
        plain = self._payload_to_bytes(payload)
        dynamic_key = self._current_dynamic_key()
        b_raw = AegisCrypto.encrypt_business_data(
            plain,
            static_key=self.config.static_key,
            dynamic_key=dynamic_key,
        )
        s_raw = AegisCrypto.wrap_dynamic_key(
            self.wrap_plaintext_builder(dynamic_key, self.public_key_info),
            peer_public_key=self.public_key_info.public_key,
            salt=self.config.hkdf_salt,
            info=self.config.hkdf_info,
        )
        r_raw = AegisCrypto.encrypt_version_info(
            self.version_plaintext_builder(self.public_key_info),
            static_key=self.config.static_key,
        )
        return urllib.parse.urlencode({"B": b64e(b_raw), "S": b64e(s_raw), "R": b64e(r_raw)})

    def decrypt_xeapi_body(
        self,
        form_body: str,
        *,
        dynamic_key: bytes | None = None,
        private_key_for_s: x25519.X25519PrivateKey | None = None,
    ) -> dict[str, bytes]:
        values = urllib.parse.parse_qs(form_body, keep_blank_values=True)
        out: dict[str, bytes] = {}
        if "B" in values:
            key = dynamic_key or self.session_key or self.dynamic_key
            out["B_plain"] = AegisCrypto.decrypt_business_data(
                b64d(values["B"][0]),
                static_key=self.config.static_key,
                dynamic_key=key,
            )
        if "R" in values:
            out["R_plain"] = AegisCrypto.decrypt_version_info(
                b64d(values["R"][0]),
                static_key=self.config.static_key,
            )
        if "S" in values and private_key_for_s is not None:
            out["S_plain"] = AegisCrypto.unwrap_dynamic_key_for_test(
                b64d(values["S"][0]),
                own_private_key=private_key_for_s,
                salt=self.config.hkdf_salt,
                info=self.config.hkdf_info,
            )
        return out

    def decrypt_response_body(self, response_text: str | bytes, *, key: bytes | None = None) -> bytes:
        """
        Decrypt an encrypted /xeapi response body.

        HAR stores these response bodies as base64 text. The native response path
        appears to use the active session/dynamic key. If decrypting an offline
        HAR, pass the exact key captured from the running client; it cannot be
        derived from B/S/R alone.
        """

        active_key = self._normalize_aes_key(key or self.session_key or self.dynamic_key)
        raw = b64d(response_text.decode("ascii") if isinstance(response_text, bytes) else response_text)
        return AegisCrypto.aes_decrypt(active_key, raw, mode=1)

    def post_xeapi(
        self,
        url: str,
        payload: Mapping[str, Any] | str | bytes,
        *,
        headers: MutableMapping[str, str] | None = None,
    ) -> requests.Response:
        headers = dict(headers or {})
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        headers["X-Client-Enc-State"] = "ENCRYPTED"
        response = self.session.post(url, data=self.encrypt_xeapi_body(payload), headers=headers, timeout=20)
        self.handle_response_headers(response.headers)
        return response

    def handle_response_headers(self, headers: Mapping[str, str]) -> None:
        lower = {k.lower(): v for k, v in headers.items()}
        ssid = lower.get("x-encr-ssid")
        sskey = lower.get("x-encr-sskey")
        if ssid and sskey:
            self.session_id = ssid
            self.session_key = decode_session_key(sskey)
        sts = lower.get("x-ud-sts")
        if sts in {"10000", "20002"}:
            self.public_key_info = self.fetch_public_key(active=False)
        elif sts == "8888":
            raise RuntimeError("server entered global decrypt fallback (x-ud-sts=8888)")

    def _current_dynamic_key(self) -> bytes:
        if self.session_key:
            return self._normalize_aes_key(self.session_key)
        now = time.time()
        if now - self.dynamic_key_time >= self.config.update_interval_seconds:
            self.dynamic_key = os.urandom(16)
            self.dynamic_key_time = now
        return self.dynamic_key

    @staticmethod
    def _normalize_aes_key(key: bytes) -> bytes:
        if len(key) in (16, 24, 32):
            return key
        return hashlib.sha256(key).digest()[:16]

    @staticmethod
    def _payload_to_bytes(payload: Mapping[str, Any] | str | bytes) -> bytes:
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, str):
            return payload.encode("utf-8")
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @staticmethod
    def default_key_request_signer(sign_key: bytes, timestamp: str, nonce: str) -> str:
        # Native sub_52b8d4 signs timestamp+nonce with HMAC-SHA256, and
        # UpdatePublicKey base64-encodes the raw digest into the JSON body.
        digest = hmac.new(sign_key, (timestamp + nonce).encode("utf-8"), hashlib.sha256).digest()
        return b64e(digest)

    @staticmethod
    def default_wrap_plaintext(dynamic_key: bytes, info: PublicKeyInfo, os_name: str = "android") -> bytes:
        # Native builds base64(dynamicKey) + "|" + os + "|" + sk.
        # wrap_suffix remains an escape hatch for byte-for-byte calibration.
        suffix = info.wrap_suffix if info.wrap_suffix is not None else f"|{os_name}|{info.sk}"
        return b64e(dynamic_key).encode("ascii") + suffix.encode("utf-8")

    @staticmethod
    def default_version_plaintext(info: PublicKeyInfo, session_id: str = "") -> bytes:
        suffix = info.version_suffix if info.version_suffix is not None else session_id
        return f"{info.version}|{suffix}".encode("utf-8")


def load_public_key_file(path: str) -> PublicKeyInfo:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return PublicKeyInfo.from_json(data)


def decode_key(value: str) -> bytes:
    """
    Decode a key argument.

    Accepted forms:
    - hex:001122...
    - b64:AAAA...
    - raw text, encoded as UTF-8
    """

    if value.startswith("hex:"):
        return bytes.fromhex(value[4:])
    if value.startswith("b64:"):
        return b64d(value[4:])
    return value.encode("utf-8")


def decode_session_key(value: str) -> bytes:
    """
    Decode session material from response headers.

    NetEase commonly emits x-encr-sskey as bare hex, while the session id
    remains an opaque ASCII token. Treat obvious hex as raw bytes so AES uses
    the real key material instead of the printable representation.
    """

    stripped = value.strip()
    if stripped and len(stripped) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in stripped):
        return bytes.fromhex(stripped)
    return stripped.encode("utf-8")


def demo_selftest() -> None:
    static_key = os.urandom(16)
    sign_key = os.urandom(16)
    server_private = x25519.X25519PrivateKey.generate()
    server_public = server_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_info = PublicKeyInfo(public_key=server_public, version="1", sk="x" * 40)
    client = AegisXeapiClient(
        AegisConfig(static_key=static_key, sign_key=sign_key, device_id="demo-device"),
        public_key_info=public_info,
    )
    body = client.encrypt_xeapi_body({"hello": "world"})
    decoded = client.decrypt_xeapi_body(body, private_key_for_s=server_private)
    assert json.loads(decoded["B_plain"].decode("utf-8")) == {"hello": "world"}
    assert decoded["S_plain"].startswith(b64e(client.dynamic_key).encode("ascii"))
    assert decoded["S_plain"].endswith(b"|android|" + (b"x" * 40))
    assert decoded["R_plain"] == b"1|"
    print(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Aegis /xeapi Python client scaffold")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_self = sub.add_parser("selftest", help="run local encryption/decryption self-test")
    p_self.set_defaults(func=lambda _args: demo_selftest())

    p_enc = sub.add_parser("encrypt", help="encrypt a JSON/plain payload into B/S/R form")
    p_enc.add_argument("--static-key", required=True, help="static AES key: hex:/b64:/raw")
    p_enc.add_argument("--sign-key", default="demo-sign-key-16", help="sign key: hex:/b64:/raw")
    p_enc.add_argument("--device-id", default="python-device")
    p_enc.add_argument("--public-key-json", required=True, help="JSON file containing publicKey/version/sk")
    p_enc.add_argument("--payload", required=True, help="JSON string or raw plaintext")
    p_enc.add_argument("--wrap-suffix", help="override S plaintext suffix after base64(dynamicKey)")
    p_enc.add_argument("--version-suffix", help="override R plaintext suffix after version|")

    def do_encrypt(args: argparse.Namespace) -> None:
        public_info = load_public_key_file(args.public_key_json)
        if args.wrap_suffix is not None or args.version_suffix is not None:
            public_info = dataclasses.replace(
                public_info,
                wrap_suffix=args.wrap_suffix,
                version_suffix=args.version_suffix,
            )
        client = AegisXeapiClient(
            AegisConfig(
                static_key=decode_key(args.static_key),
                sign_key=decode_key(args.sign_key),
                device_id=args.device_id,
            ),
            public_key_info=public_info,
        )
        payload: Mapping[str, Any] | str
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError:
            payload = args.payload
        print(client.encrypt_xeapi_body(payload))

    p_enc.set_defaults(func=do_encrypt)

    p_dec = sub.add_parser("decrypt-form", help="decrypt B/R fields when dynamic/session key is known")
    p_dec.add_argument("--static-key", required=True, help="static AES key: hex:/b64:/raw")
    p_dec.add_argument("--dynamic-key", required=True, help="dynamic/session AES key: hex:/b64:/raw")
    p_dec.add_argument("--form-body", required=True)

    def do_decrypt_form(args: argparse.Namespace) -> None:
        client = AegisXeapiClient(
            AegisConfig(
                static_key=decode_key(args.static_key),
                sign_key=b"unused-sign-key16",
                device_id="offline",
            )
        )
        decoded = client.decrypt_xeapi_body(args.form_body, dynamic_key=decode_key(args.dynamic_key))
        for name, value in decoded.items():
            print(f"{name}: {value!r}")

    p_dec.set_defaults(func=do_decrypt_form)

    p_resp = sub.add_parser("decrypt-response", help="decrypt base64 response body when key is known")
    p_resp.add_argument("--static-key", required=True, help="static AES key: hex:/b64:/raw; kept for config parity")
    p_resp.add_argument("--key", required=True, help="response dynamic/session key: hex:/b64:/raw")
    p_resp.add_argument("--body", required=True, help="base64 response body")

    def do_decrypt_response(args: argparse.Namespace) -> None:
        client = AegisXeapiClient(
            AegisConfig(
                static_key=decode_key(args.static_key),
                sign_key=b"unused-sign-key16",
                device_id="offline",
            )
        )
        print(client.decrypt_response_body(args.body, key=decode_key(args.key)))

    p_resp.set_defaults(func=do_decrypt_response)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
