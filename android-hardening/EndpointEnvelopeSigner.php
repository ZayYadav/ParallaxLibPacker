<?php
declare(strict_types=1);

/**
 * Server-side example for ParallaxSignedEndpoint.java.
 *
 * Requirements:
 *   - PHP ext-sodium
 *   - PARALLAX_ED25519_SECRET_KEY_FILE points to a file OUTSIDE the web root.
 *
 * Request fields expected here are examples. Bind them to your authenticated
 * session/device record in production; do not trust arbitrary client values.
 */

header('Content-Type: application/json; charset=utf-8');

const ENDPOINT_URL = 'https://parallaxloadersdk.parallaxserver.online/connect.php';
const TTL_SECONDS = 120;

function fail(int $status, string $message): never {
    http_response_code($status);
    echo json_encode(['status' => 'error', 'message' => $message], JSON_UNESCAPED_SLASHES);
    exit;
}

if (!extension_loaded('sodium')) {
    fail(500, 'Server crypto unavailable');
}

$deviceId = isset($_POST['device_id']) ? trim((string) $_POST['device_id']) : '';
$nonce = isset($_POST['nonce']) ? trim((string) $_POST['nonce']) : '';

if ($deviceId === '' || strlen($deviceId) > 256) {
    fail(400, 'Invalid device_id');
}
if ($nonce === '' || strlen($nonce) < 16 || strlen($nonce) > 256) {
    fail(400, 'Invalid nonce');
}

$keyFile = getenv('PARALLAX_ED25519_SECRET_KEY_FILE');
if ($keyFile === false || $keyFile === '' || !is_readable($keyFile)) {
    fail(500, 'Signing key unavailable');
}

$keyText = trim((string) file_get_contents($keyFile));
try {
    $secretKey = sodium_base642bin($keyText, SODIUM_BASE64_VARIANT_ORIGINAL);
} catch (Throwable $e) {
    fail(500, 'Signing key malformed');
}

if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    fail(500, 'Signing key has wrong size');
}

$expiresAt = time() + TTL_SECONDS;
// Monotonic/version value can instead come from your DB configuration row.
$version = (int) floor(microtime(true) * 1000);
$url = ENDPOINT_URL;

$canonical = $version . "\n"
    . $expiresAt . "\n"
    . $deviceId . "\n"
    . $nonce . "\n"
    . $url;

$signature = sodium_crypto_sign_detached($canonical, $secretKey);

// Best-effort wipe of the local secret-key buffer.
sodium_memzero($secretKey);

echo json_encode([
    'status' => 'success',
    'version' => $version,
    'expires_at' => $expiresAt,
    'device_id' => $deviceId,
    'nonce' => $nonce,
    'url' => $url,
    'signature' => sodium_bin2base64($signature, SODIUM_BASE64_VARIANT_ORIGINAL),
], JSON_UNESCAPED_SLASHES);
