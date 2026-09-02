# Android endpoint hardening

This directory contains application-layer hardening for the common attack where a runtime hook replaces an SDK URL/string and redirects requests to another server.

## What this protects

`ParallaxSignedEndpoint.java` verifies a short-lived Ed25519-signed endpoint envelope. The signature covers:

- version
- expiry timestamp
- device ID
- client nonce
- exact HTTPS URL

Changing the URL alone after receiving the server response invalidates the signature. The URI is also restricted to `https://parallaxloadersdk.parallaxserver.online` and port 443.

This is deliberately different from relying on a secret HMAC key embedded in the APK. A client-side HMAC secret can eventually be extracted. With Ed25519, the APK contains only the public verification key; the private signing key remains on the server.

## Server setup

1. Generate an Ed25519 key pair on a trusted machine/server.
2. Keep the secret key outside the web root with restrictive filesystem permissions.
3. Set `PARALLAX_ED25519_SECRET_KEY_FILE` to the secret-key file path.
4. Put the X.509/SPKI Base64 public key into `ParallaxSignedEndpoint.PUBLIC_KEY_X509_B64`.
5. Integrate `EndpointEnvelopeSigner.php` into the authenticated license/session endpoint instead of exposing it as an unauthenticated standalone signer.

The included PHP code is an integration example. In production, derive `device_id` from your authenticated device/session record where possible rather than trusting an arbitrary posted value.

## Android flow

1. Generate a cryptographically random nonce on the device.
2. Send the nonce as part of the authenticated SDK request.
3. Server returns `version`, `expires_at`, `device_id`, `nonce`, `url`, and `signature`.
4. Call `ParallaxSignedEndpoint.verifyAndGetUri(...)`.
5. Build the network request directly from the returned `URI` object. Do not verify one global URL and later fetch a second mutable global URL.
6. Reject the request immediately if verification fails.

Example nonce generation:

```java
byte[] n = new byte[32];
new java.security.SecureRandom().nextBytes(n);
String nonce = android.util.Base64.encodeToString(
        n,
        android.util.Base64.NO_WRAP | android.util.Base64.URL_SAFE);
```

## TLS pinning

Use certificate/public-key pinning in the network stack as an additional layer. If using OkHttp, configure `CertificatePinner` for the expected host using the real SPKI SHA-256 pin from your production certificate chain. Maintain a backup pin to avoid locking out legitimate certificate rotation.

Do not invent or hard-code a placeholder certificate pin.

## Native build hardening

For libraries you build from source, use Android NDK hardening where supported:

```cmake
target_compile_options(yourlib PRIVATE
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fvisibility=hidden)

target_link_options(yourlib PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack)
```

Export only the JNI/native symbols that must remain public. Keep sensitive authorization decisions server-side.

## Important limitation

No code executing inside a user-controlled/rooted process can be made universally "unhookable." A sufficiently privileged attacker can patch code, alter return values, or replace network calls. The goal here is to make a simple `strlen`/string/URL hook insufficient: a redirected endpoint no longer has a valid server signature and the client refuses it.

For important authorization, the server must still validate license state, device binding, nonce/freshness and request/session state independently. Never trust a client boolean such as `isLicensed=true` as the security boundary.
