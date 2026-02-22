<?php

declare(strict_types=1);

// bin/generate-keys.php (for Ed25519)

if (!extension_loaded('sodium')) {
    echo "Error: The libsodium extension is required to generate Ed25519 keys. Please enable it in your PHP configuration.\n";
    exit(1);
}

$privateKeyFilename = 'ed25519_private.key'; // Stores base64 encoded private key
$publicKeyFilename = 'ed25519_public.key';  // Stores base64 encoded public key

if (file_exists($privateKeyFilename) || file_exists($publicKeyFilename)) {
    echo "Error: '{$privateKeyFilename}' or '{$publicKeyFilename}' already exist in the current directory.\n";
    echo "Please remove them or run this script in a different directory.\n";
    exit(1);
}

// --- Ed25519 Key Generation ---
echo "Generating Ed25519 key pair...\n";
$keypair = sodium_crypto_sign_keypair();
$secretKey = sodium_crypto_sign_secretkey($keypair); // This is the sk part, 64 bytes
$publicKey = sodium_crypto_sign_publickey($keypair);   // This is the pk part, 32 bytes

$base64SecretKey = base64_encode($secretKey);
$base64PublicKey = base64_encode($publicKey);

if (file_put_contents($privateKeyFilename, $base64SecretKey) === false) {
    echo "Error: Could not save base64 encoded private key to {$privateKeyFilename}.\n";
    exit(1);
}
echo "Base64 encoded Ed25519 private key saved to: {$privateKeyFilename} (Used by the middleware)\n";

if (file_put_contents($publicKeyFilename, $base64PublicKey) === false) {
    echo "Error: Could not save base64 encoded public key to {$publicKeyFilename}.\n";
    exit(1);
}
echo "Base64 encoded Ed25519 public key saved to: {$publicKeyFilename} (For reference or other uses)\n\n";

// --- JWK and Kid Generation for Ed25519 ---

/**
 * Base64url encodes data.
 */
function base64url_encode_ed_genkeys(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// For Ed25519 JWK, 'x' is the public key (32 bytes), base64url encoded.
$x_b64url = base64url_encode_ed_genkeys($publicKey);

/**
 * Calculates the JWK thumbprint for an Ed25519 public key.
 * Required members for Ed25519 JWK: crv, kty, x
 */
function calculate_jwk_thumbprint_ed_genkeys(string $x_b64url): string
{
    $jwkMembers = [
        'crv' => 'Ed25519',
        'kty' => 'OKP',       // Octet Key Pair
        'x'   => $x_b64url,
    ];
    ksort($jwkMembers); // Sort by key for canonical form (crv, kty, x)
    $canonicalJson = json_encode($jwkMembers, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $hash = hash('sha256', $canonicalJson, true);
    return base64url_encode_ed_genkeys($hash);
}

$kid = calculate_jwk_thumbprint_ed_genkeys($x_b64url);

$jwk = [
    'kty' => 'OKP',
    'crv' => 'Ed25519',
    'x'   => $x_b64url,
    'kid' => $kid,
    'alg' => 'Ed25519',
    'use' => 'sig'
];

try {
    $jwkJson = json_encode($jwk, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
} catch (\JsonException $e) {
    echo "Error: Failed to encode JWK JSON: {$e->getMessage()}\n";
    exit(1);
}

echo "--- Configuration for WebBotAuthMiddleware (Ed25519) ---\n";
echo "Base64 Encoded Ed25519 Private Key (content of '{$privateKeyFilename}', for middleware constructor):
{$base64SecretKey}\n\n";
echo "JWK Thumbprint (use as 'keyId'):\n{$kid}\n\n";
echo "Full Ed25519 JWK (host this at your 'signatureAgent' URL, typically in a JWKSet):\n";
echo $jwkJson . "\n\n";
echo "Instructions for use:\n";
echo "1. The base64 encoded private key (content of '{$privateKeyFilename}' or printed above) is passed to the Guzzle middleware.
";
echo "2. The 'keyId' above ('{$kid}') is passed to the middleware constructor.
";
echo "3. The 'Full Ed25519 JWK' JSON above should be made available at your 'signatureAgent' URL.
   (e.g., in a 'keys' array within a JSON object at https://your-bot.example.com/.well-known/http-message-signatures-directory)
";

exit(0);
