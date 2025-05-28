<?php

// bin/generate-jwk.php (for Ed25519 from existing base64 public key)

if (!extension_loaded('sodium')) {
    echo "Error: The libsodium extension is required. Please enable it in your PHP configuration.\n";
    exit(1);
}

if ($argc < 2) {
    echo "Usage: php generate-jwk.php <base64_encoded_ed25519_public_key_string_or_path_to_file>\n";
    echo "Example (string): php generate-jwk.php MCowBQYDK2VwAyEAGb642+kV3as4kPcBw0n0xM7rtksZCAVnB3i5W2e3L9M=\n";
    echo "Example (file):   php generate-jwk.php path/to/your/ed25519_public.key\n";
    exit(1);
}

$publicKeyInput = $argv[1];
$base64PublicKey = '';

if (file_exists($publicKeyInput)) {
    $content = file_get_contents($publicKeyInput);
    if ($content === false) {
        echo "Error: Could not read public key from file: {$publicKeyInput}\n";
        exit(1);
    }
    $base64PublicKey = trim(preg_replace('/\s+/', '', $content));
} else {
    $base64PublicKey = trim(preg_replace('/\s+/', '', $publicKeyInput));
}

if (empty($base64PublicKey)) {
    echo "Error: Public key input is empty.\n";
    exit(1);
}

$publicKeyBytes = base64_decode($base64PublicKey, true);
if ($publicKeyBytes === false || strlen($publicKeyBytes) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
    echo "Error: Invalid Ed25519 public key. Must be a base64 encoded string representing " . SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES . " bytes.\n";
    echo "Received length after base64 decode: " . ($publicKeyBytes === false ? 'decode_failed' : strlen($publicKeyBytes)) . " bytes.\n";
    exit(1);
}

/**
 * Base64url encodes data.
 */
function base64url_encode_ed_jwk(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

$x_b64url = base64url_encode_ed_jwk($publicKeyBytes);

/**
 * Calculates the JWK thumbprint for an Ed25519 public key.
 */
function calculate_jwk_thumbprint_ed_jwk(string $x_b64url): string
{
    $jwkMembers = [
        'crv' => 'Ed25519',
        'kty' => 'OKP',
        'x'   => $x_b64url,
    ];
    ksort($jwkMembers);
    $canonicalJson = json_encode($jwkMembers, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $hash = hash('sha256', $canonicalJson, true);
    return base64url_encode_ed_jwk($hash);
}

$kid = calculate_jwk_thumbprint_ed_jwk($x_b64url);

$jwk = [
    'kty' => 'OKP',
    'crv' => 'Ed25519',
    'x'   => $x_b64url,
    'kid' => $kid,
    'alg' => 'Ed25519',
    'use' => 'sig'
];

echo "--- Ed25519 JWK Details ---\n";
echo "Input Base64 Public Key: {$base64PublicKey}\n\n";
echo "JWK Thumbprint (kid):\n{$kid}\n\n";
echo "Full Ed25519 JWK (for your .well-known/jwks.json file):
";
echo json_encode($jwk, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";

exit(0); 