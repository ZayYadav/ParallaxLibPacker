import android.util.Base64;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

/**
 * Defensive endpoint guard for Android SDKs.
 *
 * The server signs: version + expiry + deviceId + nonce + url.
 * A simple in-memory URL/string replacement therefore does not produce a
 * valid endpoint envelope. Keep the private signing key on the server only.
 *
 * Requires an Android/JCA provider with Ed25519 support (API 28+ on modern
 * Android builds). Replace PUBLIC_KEY_X509_B64 with the Base64 X.509 Subject
 * Public Key Info for your Ed25519 public key.
 */
public final class ParallaxSignedEndpoint {
    private static final String EXPECTED_HOST = "parallaxloadersdk.parallaxserver.online";
    private static final String PUBLIC_KEY_X509_B64 =
            "REPLACE_WITH_YOUR_ED25519_X509_PUBLIC_KEY_BASE64";

    // Keep endpoint envelopes short lived to make replay less useful.
    private static final long MAX_FUTURE_TTL_SECONDS = 5 * 60L;

    private ParallaxSignedEndpoint() {}

    public static URI verifyAndGetUri(
            String url,
            long version,
            long expiresAtEpochSeconds,
            String deviceId,
            String nonce,
            String signatureB64) throws Exception {

        if (url == null || deviceId == null || nonce == null || signatureB64 == null) {
            throw new SecurityException("Missing signed endpoint field");
        }

        final long now = System.currentTimeMillis() / 1000L;
        if (expiresAtEpochSeconds <= now) {
            throw new SecurityException("Signed endpoint expired");
        }
        if (expiresAtEpochSeconds - now > MAX_FUTURE_TTL_SECONDS) {
            throw new SecurityException("Signed endpoint TTL too large");
        }
        if (version <= 0L) {
            throw new SecurityException("Invalid endpoint version");
        }

        final URI uri = URI.create(url);
        validateUri(uri);

        final String canonical = canonicalize(
                version,
                expiresAtEpochSeconds,
                deviceId,
                nonce,
                url);

        final PublicKey publicKey = loadPublicKey();
        final Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(canonical.getBytes(StandardCharsets.UTF_8));

        final byte[] signature = Base64.decode(signatureB64, Base64.NO_WRAP);
        if (!verifier.verify(signature)) {
            throw new SecurityException("Endpoint signature invalid");
        }

        // Return the exact URI that was covered by the signature. Do not
        // re-create it from a mutable global/static URL after verification.
        return uri;
    }

    public static String canonicalize(
            long version,
            long expiresAtEpochSeconds,
            String deviceId,
            String nonce,
            String url) {
        return Long.toString(version) + "\n"
                + Long.toString(expiresAtEpochSeconds) + "\n"
                + deviceId + "\n"
                + nonce + "\n"
                + url;
    }

    private static void validateUri(URI uri) {
        if (uri == null) {
            throw new SecurityException("Invalid endpoint URI");
        }

        final String scheme = uri.getScheme();
        final String host = uri.getHost();

        if (scheme == null || !"https".equals(scheme.toLowerCase(Locale.US))) {
            throw new SecurityException("HTTPS required");
        }
        if (host == null || !EXPECTED_HOST.equals(host.toLowerCase(Locale.US))) {
            throw new SecurityException("Unexpected endpoint host");
        }
        if (uri.getUserInfo() != null) {
            throw new SecurityException("Endpoint userinfo not allowed");
        }
        if (uri.getFragment() != null) {
            throw new SecurityException("Endpoint fragment not allowed");
        }

        final int port = uri.getPort();
        if (port != -1 && port != 443) {
            throw new SecurityException("Unexpected endpoint port");
        }
    }

    private static PublicKey loadPublicKey() throws Exception {
        if (PUBLIC_KEY_X509_B64.startsWith("REPLACE_")) {
            throw new IllegalStateException("Configure Ed25519 public key first");
        }

        final byte[] encoded = Base64.decode(PUBLIC_KEY_X509_B64, Base64.DEFAULT);
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(encoded);
        return KeyFactory.getInstance("Ed25519").generatePublic(spec);
    }
}
