# AegisNative Java Side Analysis

## Scope

Target Java class:

```java
com.aegis.sdk.AegisNative
```

Current native library observed in Binary Ninja:

```text
D:/User/Downloads/libAegisSDK.so
```

`AegisNative` is not a business class. It is the JNI facade for the Aegis SDK used by the app network encryption / anti-crawler path.

## JNI Facade

Source shape:

```java
package com.aegis.sdk;

public class AegisNative {
    static {
        h3.c.e("AegisSDK");
    }

    public static native void destroyEngine();
    public static native String encrypt(String str);
    public static native int initializeEngine(
        String str,
        String str2,
        String str3,
        String str4,
        String str5,
        String str6,
        Object obj,
        int i15
    );
    public static native int onNetworkResponse(long j15, int i15, String str);
    public static native void setSession(String str, String str2);
    public static native void setTrackingListener(AegisTrackingListener listener);
    public static native int updatePublicKey(boolean z15);

    public interface AegisTrackingListener {
        void onTrack(String str, String str2);
    }
}
```

The library loader is `h3.c.e("AegisSDK")`, so the Java class loads `libAegisSDK.so`.

## Java Wrapper Classes

Important classes found from direct xrefs:

```text
k72.c                                      abstract encrypt config / wrapper
k72.f                                      concrete singleton config
k72.e                                      abstract native callback network layer
k72.g                                      concrete network layer
com.netease.cloudmusic.network.IEncryptService
com.netease.cloudmusic.network.encrypt.CMEncryptService
com.netease.cloudmusic.network.interceptor.m0
i82.a
k72.g0
```

`AegisNative` is used only by the wrapper layer. App code normally reaches it through `IEncryptService`.

## Initialization

`k72.f` is the concrete singleton:

```java
public final class f extends k72.c {
    public static final f f227493d = new f();
}
```

It supplies:

- public key path: `filesDir/aegissdk/public_key`
- static key: decoded from an obfuscated string via `su.a(...)`
- sign key: decoded from an obfuscated string via `su.a(...)`
- network callback layer: `k72.g.f227495d`

`k72.c.i()` initializes the native engine:

```java
AegisNative.initializeEngine(
    f(),       // public key path
    h(),       // static key
    l4.e(),    // device id
    "android",
    userOrAppField,
    g(),       // sign key
    e(),       // k72.e network layer object
    iVar.g()   // config flag/int
)
```

The wrapper stores initialization state as:

```java
initialized = (ret == 0)
```

After `k72.f.i()` calls `super.i()`, it registers the service:

```java
ServiceFacade.put(IEncryptService.class, new CMEncryptService());
```

## Service Interface

`IEncryptService` is the app-facing API:

```java
public interface IEncryptService {
    String encrypt(String data);
    boolean isSDKInitialized();
    void setSession(String sessionId, String sessionKey);
    boolean updatePublicKey(boolean isActivated);
}
```

`CMEncryptService` is a thin proxy:

```java
encrypt(data)              -> k72.f.f227493d.c(data)
isSDKInitialized()         -> k72.f.f227493d.l()
setSession(id, key)        -> k72.f.f227493d.m(id, key)
updatePublicKey(activated) -> k72.f.f227493d.n(activated)
```

Then `k72.c` calls the JNI methods:

```java
k72.c.c(data)        -> AegisNative.encrypt(data)
k72.c.m(id, key)     -> AegisNative.setSession(id, key)
k72.c.n(isActivated) -> k72.e.i(isActivated) -> AegisNative.updatePublicKey(isActivated)
```

Failure codes thrown by `k72.c.c(data)`:

```text
-2 encrypt engine not init
-3 encrypt engine init failed
-4 native encrypt threw
-5 encrypt result is null
```

## Native-to-Java Key Callback

`k72.e` exposes a method annotated for native calls:

```java
@CalledByNative
public final void requireKey(int type, String data, long callbackHandle)
```

For `type == 0`, Java schedules a network request. It parses the native-provided JSON and adds:

```text
t1
t2
os = android
appVersion
deviceId
uid
```

Then it requests:

```text
gorilla/anti/crawler/security/key/get
```

Success path:

```java
AegisNative.onNetworkResponse(callbackHandle, 200, responseString);
```

Failure path:

```java
AegisNative.onNetworkResponse(callbackHandle, -1, "");
```

This means the native Aegis engine owns the key update flow, but it delegates the actual HTTP request to Java through `k72.e.requireKey`.

## Request Encryption Interceptors

### `i82.a`

`i82.a` is an abstract OkHttp interceptor for EAPI / XEAPI request encryption.

It collects request query/body params into a map, builds a JSON payload, and when native encryption is enabled it calls:

```java
IEncryptService service = ServiceFacade.get(IEncryptService.class);
String encrypted = service.encrypt(jsonParamsString);
```

Then it rewrites:

```text
/api/ or /eapi/ -> /xeapi/
```

and sends the encrypted string as the request body.

It also sets:

```text
X-Client-Enc-State: ENCRYPTED
```

If native encryption is disabled or degraded, it falls back to the older EAPI path using its abstract:

```java
String e(String url, String plainParams);
```

There is an opt-out request header:

```text
cm_no_encrypt_native_tag_20220105: true
```

### `com.netease.cloudmusic.network.interceptor.m0`

`m0` is another OkHttp interceptor that encrypts a request tag value into headers.

If encryption is enabled and no per-request opt-out is present, it obtains:

```java
q72.m.Y0()
```

Then:

```java
String encrypted = IEncryptService.encrypt(plain);
```

and emits:

```text
X-Client-Enc-State: ENCRYPTED
x-ud-sbr: encrypted value
x-ud-op: original plain value
```

If encryption fails, it degrades and may add:

```text
X-Degrade-Reason: EncryptFailed
X-Degrade-Reason: SingleDegrade
```

## Encrypt State Manager

`k72.g0` tracks native encryption/decryption status with an `AtomicInteger encryptState`.

Observed state meanings from log strings:

```text
0 normal
1 EncryptFailed
2 GlobalDegrade
3 AutoDegrade
```

Request-side degrade header:

```text
X-Client-Enc-State: DEGRADE
X-Degrade-Reason: EncryptFailed | GlobalDegrade | AutoDegrade
```

Response headers consumed:

```text
x-de-duration
x-ud-sts
x-encr-ssid
x-encr-sskey
```

`x-ud-sts` handling:

```text
10000  decrypt success, but public key should be updated
8888   server global decrypt error, enter global degrade
20000  server decrypt failed, single fallback
20002  server decrypt key error, fallback and update public key
9999   global recovery
```

Session update:

```java
if x-encr-ssid and x-encr-sskey exist:
    IEncryptService.setSession(ssid, sskey)
    -> AegisNative.setSession(ssid, sskey)
```

Public key update:

```java
IEncryptService.updatePublicKey(false)
-> k72.c.n(false)
-> k72.e.i(false)
-> AegisNative.updatePublicKey(false)
```

`k72.e.i(...)` rate-limits public key updates using `lastUpdatePublicKeyTimeMs`.

## High-Level Flow

```text
App startup / network module
  -> k72.f.i()
  -> AegisNative.initializeEngine(...)
  -> ServiceFacade.put(IEncryptService, CMEncryptService)

Network request
  -> i82.a or m0 interceptor
  -> ServiceFacade.get(IEncryptService)
  -> CMEncryptService.encrypt(...)
  -> k72.f.c(...)
  -> AegisNative.encrypt(...)
  -> request is rewritten or headers are added

Native needs key
  -> k72.e.requireKey(type, data, callbackHandle)
  -> Java requests gorilla/anti/crawler/security/key/get
  -> AegisNative.onNetworkResponse(callbackHandle, status, body)

Server response
  -> k72.g0 reads x-ud-sts / session headers
  -> may update public key, set session, enter degrade, or recover
```

## Current Conclusion

`com.aegis.sdk.AegisNative` is the JNI entry for NetEase Cloud Music's native request encryption / anti-crawler Aegis SDK. The Java side:

1. Loads `libAegisSDK.so`.
2. Initializes the native engine with app/device identifiers, decoded static/sign keys, a public key path, and a Java callback object.
3. Exposes native encryption through `IEncryptService`.
4. Lets OkHttp interceptors rewrite or annotate requests using `AegisNative.encrypt`.
5. Handles native key-fetch callbacks by calling `gorilla/anti/crawler/security/key/get`.
6. Uses response headers to update public keys, sessions, and encryption degrade/recovery state.

## Native Layer Analysis

Binary Ninja target:

```text
D:/User/Downloads/libAegisSDK.so
```

JNI exports are explicit symbols:

```text
0x53125c Java_com_aegis_sdk_AegisNative_initializeEngine
0x5316a0 Java_com_aegis_sdk_AegisNative_encrypt
0x531788 Java_com_aegis_sdk_AegisNative_updatePublicKey
0x531794 Java_com_aegis_sdk_AegisNative_setSession
0x5318a8 Java_com_aegis_sdk_AegisNative_destroyEngine
0x5318ac Java_com_aegis_sdk_AegisNative_setTrackingListener
0x531ad8 Java_com_aegis_sdk_AegisNative_onNetworkResponse
```

These JNI functions are thin wrappers. They convert Java strings to C++ `std::string`, then call the exported Aegis C API:

```text
Aegis_InitializeEngine   0x514074
Aegis_Encrypt           0x514714
Aegis_UpdatePublicKey   0x5149b4
Aegis_SetSession        0x5149f0
Aegis_DestroyEngine     0x514bec
Aegis_SetTrackingListener 0x514c0c
```

The global native engine object is stored at:

```text
data_6fe940
```

`Aegis_InitializeEngine` creates an `AegisEngine` object when this global is empty, then calls:

```text
sub_515010(AegisEngine::Initialize)
```

`Aegis_Encrypt` checks `data_6fe940`, validates arguments, then calls:

```text
sub_516f58(AegisEngine::Encrypt)
```

## Native Initialization

`sub_515010` initializes the cryptographic helpers:

```text
arg1 + 0x08  ECCCipher
arg1 + 0x10  AESCipher(mode=1)
arg1 + 0x18  AESCipher(mode=1)
```

Confirmed constructor calls:

```text
sub_52a7b4  ECCCipher constructor
sub_52a43c  AESCipher constructor
sub_52d8f4  AESCipherSSL constructor
```

The initialization path also stores device/static config in `data_6fe9a8`, including:

```text
public key file path
static key
device id
os
ua / app field
sign key
Java network layer callback object
```

Notable initialization behavior:

1. Generates an initial dynamic key with `sub_52be10(0x80, deviceId, os, out)`.
2. Stores dynamic key metadata with timestamp and update interval through `sub_52b384`.
3. Reads and base64-decodes the local public key file.
4. Parses the decoded public key JSON for:

```text
publicKey
version
sk
nextUpdateTime
```

5. Logs and stores the public key/version data.
6. Always triggers `UpdatePublicKey(true)` during initialization.

Observed native log strings:

```text
Initializing AegisEngine
Initialized Device Info: OS=%s, DeviceID=%s, UA=%s, signKey=%s
Initialized Dynamic Key: %s, Time: %lld, Interval: %d
Read local public key: version=%s, expireTime=%lld, sk=%s,publicKey=%s
Always updating public key on initialization.
```

## Native Encrypt Flow

Core function:

```text
sub_516f58(AegisEngine::Encrypt)
```

High-level flow:

```text
input plaintext
  -> choose dynamic key
  -> EncryptBusinessData(...)  -> cipherB
  -> EncryptDynamicKey(...)    -> cipherS
  -> EncryptVersionInfo(...)   -> cipherR
  -> URL-escape each component
  -> concatenate final output
```

The three main child functions are:

```text
sub_518538  EncryptBusinessData
sub_518738  EncryptDynamicKey
sub_518bf0  EncryptVersionInfo
```

The output is not one simple ciphertext. Runtime HAR samples show that the native result is emitted as an `application/x-www-form-urlencoded` body with three fields:

```text
B=<cipherB>&S=<cipherS>&R=<cipherR>
```

Before concatenation, each component goes through:

```text
sub_52f1a8  base64 encode
sub_52ff0c  URL-style escaping
```

The URL escaping leaves alphanumeric characters plus `-`, `_`, and `~` unescaped, and percent-encodes other bytes.

In older fallback EAPI mode, the request body uses a single `params` field instead.

## Dynamic Key Selection

Inside `AegisEngine::Encrypt`:

1. It checks whether a session key exists.
2. If session key is available, it uses session key as the dynamic key.
3. Otherwise it checks stored dynamic key age:

```text
now - dynamicKeyTimestamp >= intervalMinutes * 60000
```

4. If expired or missing, it generates a new dynamic key:

```text
sub_52be10(0x80, ..., ..., out)
```

5. It stores the new dynamic key with timestamp and interval:

```text
sub_52b384(data_6fe9a8, dynamicKey, now, interval)
```

Relevant logs:

```text
Using session key as dynamic key. sessionID: %s
Dynamic Key expired or missing (Expired: %d). Generating new one.
New Dynamic Key Generated.
```

`sub_52be10` appears to be a custom dynamic-key generator. It mixes:

```text
steady/system time
thread id
random bytes from RAND_bytes / random_device
hashes of input strings
```

Then it emits a byte string of requested size. For initial/dynamic key generation the requested size argument seen is `0x80`, which is likely a bit length (`128` bits, 16 bytes), because downstream AES mode selection accepts 16/24/32-byte keys.

## `cipherB`: Business Data Encryption

Function:

```text
sub_518538(AegisEngine::EncryptBusinessData)
```

Inputs:

```text
plaintext business data
dynamic key
```

Observed steps:

1. Fetch a static AES key from the engine config:

```text
sub_52b32c(data_6fe9a8, outStaticKey)
```

2. Static AES encrypts the plaintext:

```text
sub_52a554(arg1 + 0x18, plaintext, tmp, staticKey)
```

3. Base64 encodes/intermediate-transforms that result:

```text
sub_52f4c4(tmp, ...)
```

4. Dynamic AES encrypts the transformed intermediate using the dynamic key:

```text
sub_52a554(arg1 + 0x10, intermediate, cipherB, dynamicKey)
```

So `cipherB` is a two-layer AES construction:

```text
cipherB = AES_dynamicKey( transform( AES_staticKey(plaintext) ) )
```

The exact AES mode for `arg1 + 0x10` and `arg1 + 0x18` is selected by `AESCipherSSL::GetCipherType` (`sub_52da54`) from mode + key length. Both AESCipher instances are constructed with `mode=1`.

Mode mapping observed in `sub_52da54`:

```text
mode 0, key len 16/24/32 -> AES-128/192/256-CBC
mode 1, key len 16/24/32 -> AES-128/192/256-ECB
mode 2, key len 16/24/32 -> AES-128/192/256-GCM
```

This was confirmed by `sub_52da54` plus local ELF hexdump of the returned OpenSSL cipher descriptors. The first descriptor words line up with OpenSSL NIDs:

```text
mode 0 key16 -> NID 0x1a3, block 16, key 16, iv 16, flags 0x1002
mode 0 key24 -> NID 0x1a7, block 16, key 24, iv 16, flags 0x1002
mode 0 key32 -> NID 0x1ab, block 16, key 32, iv 16, flags 0x1002

mode 1 key16 -> NID 0x1a2, block 16, key 16, iv 0,  flags 0x1001
mode 1 key24 -> NID 0x1a6, block 16, key 24, iv 0,  flags 0x1001
mode 1 key32 -> NID 0x1aa, block 16, key 32, iv 0,  flags 0x1001

mode 2 key16 -> NID 0x37f, block 1,  key 16, iv 12
mode 2 key24 -> NID 0x382, block 1,  key 24, iv 12
mode 2 key32 -> NID 0x385, block 1,  key 32, iv 12
```

Mode 2 is also confirmed by behavior: it accepts a 12-byte IV and retrieves a 16-byte GCM tag through the EVP ctrl path. Mode 1 is therefore not just "not GCM"; it is AES-ECB with PKCS#7 padding through `EVP_EncryptFinal_ex`.

`sub_52f4c4` is the transform between the static and dynamic AES layers. It is not plain base64. The confirmed shape is:

```text
rand16 = random(16)
xored = staticCipher XOR rand16 repeated
b64 = base64(xored)
rot = rotate_left(b64, rand16[0] & 0x0f)
intermediate = rand16 || rot
```

Failure offsets:

```text
static AES failure  -> native error + 0x12c
dynamic AES failure -> native error + 0xc8
```

## `cipherS`: Dynamic Key Wrapping

Function:

```text
sub_518738(AegisEngine::EncryptDynamicKey)
```

Inputs:

```text
dynamic key
server public key
```

Observed steps:

1. Fetch public key/version metadata:

```text
sub_52b228(data_6fe9a8, outPublicKeyInfo)
sub_52b59c(data_6fe9a8, outVersionOrSkInfo)
```

2. Base64-decode the peer public key:

```text
sub_52f310(publicKey, decodedPeerKey)
```

3. Require decoded peer key length to be exactly 32 bytes.

4. Run ECDH:

```text
ECCCipherSSL::ECDH(...)
```

The error strings identify this as X25519/ECDH:

```text
X25519
X25519 Derive: Invalid peer key length %zu
ECCCipher: ECDH failed
```

5. Run HKDF-SHA256 over the shared secret:

```text
ECCCipher: HKDF failed
```

The HKDF helper is `sub_52fbe0(secret, salt, info, outLen, out)`. Its structure matches RFC 5869:

```text
if salt is empty:
    salt = 32 zero bytes
prk = HMAC-SHA256(salt, secret)
T(1) = HMAC-SHA256(prk, info || 0x01)
T(n) = HMAC-SHA256(prk, T(n-1) || info || n)
```

In the `cipherS` call site:

```text
secret = X25519 shared secret
salt   = 32 zero bytes
info   = ephemeral public key
outLen = 16
```

6. Generate a 12-byte IV:

```text
RAND_bytes(..., 0xc)
```

7. AES-GCM encrypts dynamic-key material using the derived key:

```text
sub_52dbbc(AESCipherSSL(mode=2), hkdfKey, iv, input, ciphertext, tag)
```

8. Final `cipherS` layout is concatenated from:

```text
ephemeral public key
iv
ciphertext
gcm tag
```

The exact field lengths visible from code:

```text
peer public key requirement: 32 bytes
IV: 12 bytes
GCM tag: 16 bytes
```

The dynamic-key wrapping input is assembled by `sub_518738` before calling the X25519/HKDF/AES-GCM wrapper. Cross-checking the decompiled append sequence with `REFERENCE.md` and the HAR lengths gives the high-confidence plaintext:

```text
wrapInput = base64(dynamicKey) || "|" || os || "|" || sk
```

The first component is explicit: `sub_52f1a8(arg2, ...)` base64-encodes the current dynamic/session key before concatenation. The two appended literal separators are visible as omitted `std::string::append(...)` source arguments in BN's decompile. The second component is the stored OS string (`android` in Java init), and the final component is the parsed public-key `sk`.

This also matches the observed HAR `S` size when a session key is present:

```text
base64(sessionKey32) = 44 bytes
"|android|"         = 9 bytes
sk sample           = 21 bytes
wrap plaintext      = 74 bytes
S raw               = 32 + 12 + 74 + 16 = 134 bytes
```

The log prints:

```text
EncryptDynamicKey input: %s
EncryptDynamicKey result: %d, cipherS: %s
```

## `cipherR`: Version Info Encryption

Function:

```text
sub_518bf0(AegisEngine::EncryptVersionInfo)
```

Observed steps:

1. Fetch public key version/info:

```text
sub_52b228(data_6fe9a8, outVersionInfo)
```

2. Fetch static AES key:

```text
sub_52b32c(data_6fe9a8, outStaticKey)
```

3. Build the plaintext:

```text
version + "|" + sessionId
```

`sub_52b858(data_6fe9a8, out)` returns the stored session pair. Its use in `AegisEngine::Encrypt` confirms the first string is logged as `sessionID`, while the second string is used as the active dynamic key. `EncryptVersionInfo` appends the first string, so `R` contains `sessionId`, not `sk`.

4. AES encrypt with the static key through the same AES wrapper:

```text
sub_52a554(arg1 + 0x18, versionPlaintext, cipherR, staticKey)
```

Observed logs:

```text
EncryptVersionInfo
EncryptVersionInfo Version is missing.
EncryptVersionInfo result: %d, cipherR: %s
```

## Public Key Update

Java calls:

```text
AegisNative.updatePublicKey(boolean)
```

Native path:

```text
Java_com_aegis_sdk_AegisNative_updatePublicKey
  -> Aegis_UpdatePublicKey
  -> sub_5164c8(AegisEngine::UpdatePublicKey)
```

`sub_5164c8` signs a request and delegates HTTP to the Java network layer callback.

It builds a JSON-like request with fields:

```text
currentKeyVersion
signature
timestamp
nonce
requestType = active | passive
```

The signing helper is `sub_52b8d4(signKey, out)`. It generates:

```text
timestamp = current system time in milliseconds, as decimal text
nonce     = 16 decimal digits
signRaw   = HMAC-SHA256(signKey, timestamp || nonce)
signature = base64(signRaw)
```

It calls into the configured Java network layer, which eventually reaches:

```java
k72.e.requireKey(...)
```

Then Java performs:

```text
gorilla/anti/crawler/security/key/get
```

and returns response data with:

```text
AegisNative.onNetworkResponse(callbackHandle, status, body)
```

Native `onNetworkResponse` invokes a stored callback object and then frees the callback handle.

### Public Key Update Response

The native response handler at `sub_528d70` was checked against `REFERENCE.md`.
For HTTP status `200`, it parses:

```text
data.encryptedData
data.signature
data.timestamp
```

It verifies the response signature as:

```text
expected = base64(HMAC-SHA256(signKey, str(data.timestamp) || requestNonce))
```

`requestNonce` is stored in the native callback object created during
`UpdatePublicKey`. On success it calls `sub_519440`, which:

```text
1. base64-decodes data.encryptedData
2. decrypts it with the static AES object (AES-ECB + PKCS#7)
3. parses publicKey/version/sk/nextUpdateTime
4. base64-encodes the decrypted JSON and writes it to the local public-key file
5. updates native public-key state
```

## Native Algorithm Summary

High-confidence pseudocode:

```text
initialize(publicKeyPath, staticKeyPathOrValue, deviceId, os, ua, signKey, networkLayer, interval):
    engine = new AegisEngine()
    engine.ecc = ECCCipher()
    engine.staticAes = AESCipher(mode=1)
    engine.dynamicAes = AESCipher(mode=1)
    engine.config = { paths, keys, device info, networkLayer }
    engine.dynamicKey = GenerateDynamicKey(0x80, deviceId, os)
    engine.loadLocalPublicKey(publicKeyPath)
    engine.updatePublicKey(active=true)

encrypt(plaintext):
    lock(engine)
    dynamicKey = sessionKey if present else stored/generated dynamicKey

    staticCipher = AES_mode1_encrypt(staticKey, plaintext)
    transformed = random16 || rotate_left(base64(staticCipher XOR random16), random16[0] & 0x0f)
    cipherB = AES_mode1_encrypt(dynamicKey, transformed)

    wrapInput = base64(dynamicKey) + "|" + os + "|" + sk
    ecdhSecret, ephemeralPub = X25519_ECDH(serverPublicKey)
    wrapKey = HKDF-SHA256(ecdhSecret, salt=zero32, info=ephemeralPub, outLen=16)
    iv = random(12)
    cipherS = ephemeralPub || iv || AES_256_GCM(wrapKey, wrapInput) || tag16

    versionPlain = version + "|" + sessionId
    cipherR = AES_mode1_encrypt(staticKey, versionPlain)

    return form_urlencode({
        "B": base64(cipherB),
        "S": base64(cipherS),
        "R": base64(cipherR)
    })
```

## `REFERENCE.md` Cross-Check

Status after targeted Binary Ninja and Jadx verification:

```text
confirmed:
  AES mode mapping: mode0=CBC, mode1=ECB, mode2=GCM
  B transform: rand16 || rotate_left(base64(staticCipher XOR rand16), rand16[0]&0xf)
  S envelope crypto: X25519, HKDF-SHA256 zero32 salt, ephemeral public key as info, AES-GCM
  S plaintext shape: base64(dynamicKey) || "|" || os || "|" || sk
  R plaintext shape: version || "|" || sessionId
  session selection: session key is used as dynamic AES key when session id/key are both present
  UpdatePublicKey request signature: base64(HMAC-SHA256(signKey, timestamp || nonce))
  UpdatePublicKey response: data.encryptedData/signature/timestamp, response signature check, then static AES decrypt
  public-key JSON fields: publicKey, version, sk, nextUpdateTime
  Java envelope class location: i82.a contains queryString / appendErKey / e_r logic

high-confidence but still needs byte capture:
  exact Java JSONObject byte order for xeapi plaintext envelope
  decoded literal static/sign keys for the exact target APK build
  whether all business response bodies use legacy eapi response decrypt

not yet implemented in Python:
  Java-style envelope builder

implemented in tool/ MITM helper:
  active key substitution for plain and encrypted key-refresh responses
  request B/S/R decrypt and S rewrap
  response decrypt attempts with legacy eapi key and session/dynamic keys
```

Open items:

```text
1. Implement Java-side xeapi plaintext envelope construction from `i82.a`.
2. Validate tool/ key-refresh encrypted response rewrite against one live flow.
3. Validate response-body decrypt modes per endpoint, including legacy eapi response key.
4. Capture one runtime dynamic/session key to validate B/S/R against the HAR byte-for-byte.
```

## HAR Runtime Sample

Sample file:

```text
D:/User/Downloads/interface3.music.163.com_2026_06_27_20_23_09.har
```

The HAR contains 6 requests:

```text
5 x /xeapi/... encrypted native requests
1 x /eapi/... legacy fallback request
```

Native encrypted requests have:

```text
X-Client-Enc-State: ENCRYPTED
Content-Type: application/x-www-form-urlencoded
form fields: B, S, R
```

The one legacy EAPI request has:

```text
form field: params
no X-Client-Enc-State
```

Observed request summary, omitting cookies/tokens and full ciphertext:

```text
idx  path                                                                          fields  B enc/raw   S enc/raw  R enc/raw  x-ud-sts  session
1    /xeapi/user/setting/minorstate/set                                            B,R,S   152/112     180/134    64/48      200       yes
2    /xeapi/user/register/device                                                   B,R,S   2860/2144   180/134    64/48      200       yes
3    /xeapi/song/lyric/v1?id=2039118938&...                                        B,R,S   236/176     180/134    64/48      200       yes
4    /eapi/link/position/show/resource                                             params  params=448  -          -          -         no
5    /xeapi/link/home/framework/top/tab                                            B,R,S   748/560     180/134    64/48      200       yes
6    /xeapi/link/home/framework/tab                                                B,R,S   1344/1008   180/134    64/48      200       yes
```

Runtime implications:

1. `R` is stable across these samples: encoded length `64`, decoded length `48`.
2. `S` is stable length: encoded length `180`, decoded length `134`.
3. `B` scales with request payload size and its decoded length is always block-aligned in these samples.
4. The stable `S` decoded length of `134` is consistent with a fixed-size dynamic-key wrapping structure:

```text
32-byte ephemeral public key
12-byte GCM IV
variable wrapped dynamic-key payload
16-byte GCM tag
```

5. Responses include `x-encr-ssid` on the encrypted requests, matching the Java/native session update path:

```text
k72.g0.n(...)
  -> IEncryptService.setSession(...)
  -> AegisNative.setSession(...)
```

## Python Reimplementation

The current Python reimplementation lives in:

```text
aegis_xeapi.py
AEGIS_PYTHON.md
```

It implements the full `/xeapi` client-side flow from cold start to encrypted communication:

```text
public-key bootstrap
dynamic key generation
B/S/R request encryption
response header state handling
request/response decryption helpers when the dynamic/session key is known
AES modes 0/1/2
```
