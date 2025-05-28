<?php

namespace Olipayne\GuzzleWebBotAuth;

use Psr\Http\Message\RequestInterface;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Uri;

class WebBotAuthMiddleware
{
    private string $base64Ed25519PrivateKey;
    private string $keyId; // JWK Thumbprint of the Ed25519 public key
    private string $signatureAgent;
    private string $tag;
    private int $expiresInSeconds;
    private string $alg = 'ed25519'; // Algorithm identifier for Ed25519 with Ed25519

    public function __construct(
        string $base64Ed25519PrivateKeyOrPath,
        string $keyId,
        string $signatureAgent,
        string $tag = 'web-bot-auth',
        int $expiresInSeconds = 300 // 5 minutes
    ) {
        if (!extension_loaded('sodium')) {
            throw new \RuntimeException('The libsodium extension is required to use Ed25519 signatures. Please enable it in your PHP configuration.');
        }

        if (file_exists($base64Ed25519PrivateKeyOrPath)) {
            $content = file_get_contents($base64Ed25519PrivateKeyOrPath);
            if ($content === false) {
                 throw new \RuntimeException("Could not read private key from file: {$base64Ed25519PrivateKeyOrPath}");
            }
            // Remove potential newlines if key is read from file
            $this->base64Ed25519PrivateKey = trim(preg_replace('/\s+/', '', $content));
        } else {
            $this->base64Ed25519PrivateKey = trim(preg_replace('/\s+/', '', $base64Ed25519PrivateKeyOrPath));
        }

        // Validate if it looks like a base64 string, crude check
        if (!preg_match('/^[a-zA-Z0-9\+\/\=]+$/', $this->base64Ed25519PrivateKey)) {
            throw new \InvalidArgumentException('Private key does not appear to be a valid base64 encoded string.');
        }
        
        $decodedKey = base64_decode($this->base64Ed25519PrivateKey, true);
        if ($decodedKey === false || (strlen($decodedKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES && strlen($decodedKey) !== SODIUM_CRYPTO_SIGN_SEEDBYTES)) {
            throw new \InvalidArgumentException(
                'Decoded Ed25519 private key must be either ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' bytes (secret key) or ' . 
                SODIUM_CRYPTO_SIGN_SEEDBYTES . ' bytes (seed). Received length: ' . strlen($decodedKey) . ' bytes.'
            );
        }

        $this->keyId = $keyId;
        $this->signatureAgent = $signatureAgent;
        $this->tag = $tag;
        $this->expiresInSeconds = $expiresInSeconds;
    }

    public function __invoke(callable $handler): callable
    {
        return function (RequestInterface $request, array $options) use ($handler): PromiseInterface {
            $created = time();
            $expires = $created + $this->expiresInSeconds;

            $signatureInputParams = [
                '("@authority" "signature-agent")',
                'created=' . $created,
                'expires=' . $expires,
                'keyid="' . $this->keyId . '"',
                'alg="' . $this->alg . '"', // Algorithm parameter
                'tag="' . $this->tag . '"',
            ];
            
            $signatureInputString = 'sig=(' . implode(' ', $signatureInputParams) . ')';

            $signatureBase = $this->createSignatureBase($request, $signatureInputString, $created, $expires);
            $signature = $this->sign($signatureBase);

            $request = $request->withHeader('Signature-Agent', $this->signatureAgent)
                               ->withHeader('Signature-Input', $signatureInputString)
                               ->withHeader('Signature', 'sig=' . base64_encode($signature));

            return $handler($request, $options);
        };
    }

    private function createSignatureBase(RequestInterface $request, string $signatureInputHeaderValueWithLabel, int $created, int $expires): string
    {
        $authority = $request->getUri()->getAuthority();

        $coveredComponents = [
            '"@authority"' => $authority,
            '"signature-agent"' => $this->signatureAgent,
        ];

        $baseStringLines = [];
        foreach ($coveredComponents as $name => $value) {
            $baseStringLines[] = $name . ': ' . $value;
        }
        
        preg_match('/^sig=\((.*)\)$/', $signatureInputHeaderValueWithLabel, $matches);
        $signatureParamsValue = $matches[1] ?? '';

        $baseStringLines[] = '"@signature-params": ' . $signatureParamsValue;

        return implode("\n", $baseStringLines);
    }

    private function sign(string $data): string
    {
        try {
            $privateKeyBytes = base64_decode($this->base64Ed25519PrivateKey, true);
            if ($privateKeyBytes === false) {
                throw new \RuntimeException('Failed to base64 decode the Ed25519 private key.');
            }

            // If it's a seed, derive the full secret key
            if (strlen($privateKeyBytes) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
                $keyPair = sodium_crypto_sign_seed_keypair($privateKeyBytes);
                $privateKeyBytes = sodium_crypto_sign_secretkey($keyPair);
            }

            if (strlen($privateKeyBytes) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
                 throw new \RuntimeException('Invalid Ed25519 private key length after potential seed expansion.');
            }

            $signature = sodium_crypto_sign_detached($data, $privateKeyBytes);
        } catch (\SodiumException $e) {
            throw new \RuntimeException('Ed25519 signing failed: ' . $e->getMessage(), 0, $e);
        }
        return $signature;
    }
} 