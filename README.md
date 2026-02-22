[![Latest Stable Version](https://img.shields.io/packagist/v/olipayne/guzzle-web-bot-auth-middleware.svg?style=flat-square)](https://packagist.org/packages/olipayne/guzzle-web-bot-auth-middleware)
[![Total Downloads](https://img.shields.io/packagist/dt/olipayne/guzzle-web-bot-auth-middleware.svg?style=flat-square)](https://packagist.org/packages/olipayne/guzzle-web-bot-auth-middleware)
[![License](https://img.shields.io/packagist/l/olipayne/guzzle-web-bot-auth-middleware.svg?style=flat-square)](https://packagist.org/packages/olipayne/guzzle-web-bot-auth-middleware)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/olipayne/guzzle-web-bot-auth-middleware/ci.yml?branch=main&style=flat-square)](https://github.com/olipayne/guzzle-web-bot-auth-middleware/actions)

# Guzzle Web Bot Auth Middleware (Ed25519 Edition)

A PHP Guzzle middleware for signing HTTP requests using HTTP Message Signatures (RFC 9421), specifically tailored for the `web-bot-auth` profile as discussed by [Cloudflare](https://blog.cloudflare.com/web-bot-auth/). This version uses Ed25519 signatures via the `libsodium` PHP extension.

## Requirements

*   PHP 7.4+ (libsodium is bundled with PHP 7.2+, but this package uses features from 7.4+)
*   The `sodium` PHP extension must be enabled.
*   GuzzleHTTP 7.0+

## Installation

Install the package via Composer:

```bash
composer require olipayne/guzzle-web-bot-auth-middleware
```

## Prerequisites & Setup (Ed25519)

To use this middleware, you need an Ed25519 private key, its corresponding public key (in JWK format hosted publicly), and a `keyid` (JWK Thumbprint of the public key). The middleware uses `alg: "ed25519"` in the `Signature-Input` header.

### Easiest Setup: All-in-One Ed25519 Key Generation Script

This package includes a utility script to generate everything you need for Ed25519:

1.  **Make the script executable** (if you haven't already):
    ```bash
    chmod +x vendor/olipayne/guzzle-web-bot-auth-middleware/bin/generate-keys.php
    ```

2.  **Run the script** from your project's root directory (or any directory where you want the key files to be saved):
    ```bash
    php vendor/olipayne/guzzle-web-bot-auth-middleware/bin/generate-keys.php
    ```
    (Path might vary based on your setup. If installed as a library, it's in `vendor/olipayne/guzzle-web-bot-auth-middleware/bin/`.)

    The script will:
    *   Create `ed25519_private.key` (containing the base64 encoded Ed25519 private key - **KEEP THIS SAFE AND SECRET!**).
    *   Create `ed25519_public.key` (containing the base64 encoded Ed25519 public key, for your reference).
    *   Output the **Base64 Encoded Ed25519 Private Key**: You'll pass this (or the path to `ed25519_private.key`) to the middleware.
    *   Output the **JWK Thumbprint (kid)**: This is the `keyid` for the middleware.
    *   Output the **Full Ed25519 JWK**: This is the JSON structure of your public key to host publicly.

    Example output snippet:
    ```
    Base64 encoded Ed25519 private key saved to: ed25519_private.key (Used by the middleware)
    Base64 encoded Ed25519 public key saved to: ed25519_public.key (For reference or other uses)

    --- Configuration for WebBotAuthMiddleware (Ed25519) ---
    Base64 Encoded Ed25519 Private Key (content of 'ed25519_private.key', for middleware constructor):
    YOUR_BASE64_ENCODED_ED25519_PRIVATE_KEY

    JWK Thumbprint (use as 'keyId'):
    YOUR_GENERATED_ED25519_KEY_ID

    Full Ed25519 JWK (host this at your 'signatureAgent' URL, typically in a JWKSet):
    {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "...base64url_encoded_public_key...",
        "kid": "YOUR_GENERATED_ED25519_KEY_ID",
        "alg": "Ed25519",
        "use": "sig"
    }
    ...
    ```

3.  **Host Your Public Key (JWKSet)**
    The `Signature-Agent` header in your requests will point to a URL where the server can fetch your public key (the "Full Ed25519 JWK" from the script) to verify the signature.

    A common practice is `https://your-bot.example.com/.well-known/jwks.json`.
    The content of `jwks.json` should be:
    ```json
    {
      "keys": [
        // The "Full Ed25519 JWK" output from the script goes here
        {
          "kty": "OKP",
          "crv": "Ed25519",
          "x": "...base64url_encoded_public_key...",
          "kid": "YOUR_GENERATED_ED25519_KEY_ID",
          "alg": "Ed25519",
          "use": "sig"
        }
      ]
    }
    ```
    Ensure this URL is publicly accessible.

### Using an Existing Ed25519 Public Key

If you already have a base64 encoded Ed25519 public key and need its JWK and `kid`:

1.  Make the `generate-jwk.php` script executable:
    ```bash
    chmod +x vendor/olipayne/guzzle-web-bot-auth-middleware/bin/generate-jwk.php
    ```
2.  Run it with your base64 encoded Ed25519 public key string or the path to a file containing it:
    ```bash
    # Using a string
    php vendor/olipayne/guzzle-web-bot-auth-middleware/bin/generate-jwk.php YOUR_BASE64_PUBLIC_KEY_STRING

    # Using a file
    php vendor/olipayne/guzzle-web-bot-auth-middleware/bin/generate-jwk.php path/to/your/ed25519_public.key
    ```
    This will output the `kid` and the full JWK for your existing public key.
3.  You will need your corresponding Ed25519 private key (base64 encoded) to configure the middleware.
4.  Host the public JWK as described in Step 3 of the "Easiest Setup".

## Usage

Provide the base64 encoded Ed25519 private key (or the path to the file like `ed25519_private.key`), your `keyid`, and your `signatureAgent` URL to the middleware.

```php
<?php

require 'vendor/autoload.php';

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Olipayne\GuzzleWebBotAuth\WebBotAuthMiddleware;

// Ensure libsodium is available
if (!extension_loaded('sodium')) {
    die('Libsodium extension is required!');
}

// 1. Create a Guzzle HandlerStack
$stack = HandlerStack::create();

// 2. Configure the WebBotAuthMiddleware
// Option A: Path to the file containing the base64 encoded private key
$privateKeyPath = 'path/to/your/ed25519_private.key'; 
// Option B: The base64 encoded private key string directly
// $base64PrivateKey = 'YOUR_BASE64_ENCODED_ED25519_PRIVATE_KEY_FROM_SCRIPT_OUTPUT';

$keyId = 'YOUR_GENERATED_ED25519_KEY_ID'; // The JWK Thumbprint from the script output
$signatureAgentUrl = 'https://your-bot.example.com/.well-known/jwks.json'; // URL to your public JWKSet

$botAuthMiddleware = new WebBotAuthMiddleware(
    $privateKeyPath, // or $base64PrivateKey
    $keyId,
    $signatureAgentUrl
    // Optional tag and expires duration remain the same
);

// 3. Push the middleware onto the stack
$stack->push($botAuthMiddleware);

// 4. Create the Guzzle client with the handler stack
$client = new Client(['handler' => $stack]);

// Requests are now signed using Ed25519
try {
    $response = $client->get('https://target-service.example.com/api/data');
    // ...
} catch (\Exception $e) {
    // ...
}
?>
```

### Covered Components & Algorithm

*   **Covered Components:** `("@authority" "signature-agent")`
*   **Signature Algorithm (in `Signature-Input`):** `alg="ed25519"`
*   **JWK Algorithm (`alg` in JWK):** `Ed25519`

## How it Works

The middleware uses `sodium_crypto_sign_detached` for Ed25519 signatures. The `Signature-Input` header includes an `alg="ed25519"` parameter. The JWK for the public key uses `kty: "OKP"` (Octet Key Pair) and `crv: "Ed25519"`.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## Releases

See `RELEASE.md` for the tag-based release and Packagist publishing process.

## License

This package is open-sourced software licensed under the [MIT license](LICENSE.MIT).
