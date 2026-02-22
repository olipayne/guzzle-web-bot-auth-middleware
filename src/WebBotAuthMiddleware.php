<?php

declare(strict_types=1);

namespace Olipayne\GuzzleWebBotAuth;

use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;

class WebBotAuthMiddleware
{
    private const SIGNATURE_ALG = 'ed25519';

    private string $ed25519SecretKey;
    private string $keyId; // JWK Thumbprint of the Ed25519 public key
    private string $signatureAgent;
    private string $tag;
    private int $expiresInSeconds;

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
            $base64Ed25519PrivateKey = $this->normalizeKeyInput($content);
        } else {
            $base64Ed25519PrivateKey = $this->normalizeKeyInput($base64Ed25519PrivateKeyOrPath);
        }

        if (preg_match('/^[A-Za-z0-9+\/]*={0,2}$/', $base64Ed25519PrivateKey) !== 1) {
            throw new \InvalidArgumentException('Private key does not appear to be a valid base64 encoded string.');
        }

        $decodedKey = base64_decode($base64Ed25519PrivateKey, true);
        $decodedKeyLength = is_string($decodedKey) ? strlen($decodedKey) : 'decode_failed';

        if ($decodedKey === false || (strlen($decodedKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES && strlen($decodedKey) !== SODIUM_CRYPTO_SIGN_SEEDBYTES)) {
            throw new \InvalidArgumentException(
                'Decoded Ed25519 private key must be either ' . SODIUM_CRYPTO_SIGN_SECRETKEYBYTES . ' bytes (secret key) or ' .
                SODIUM_CRYPTO_SIGN_SEEDBYTES . ' bytes (seed). Received length: ' . $decodedKeyLength . ' bytes.'
            );
        }

        if (strlen($decodedKey) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            $keyPair = sodium_crypto_sign_seed_keypair($decodedKey);
            $decodedKey = sodium_crypto_sign_secretkey($keyPair);
        }

        if (strlen($decodedKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new \RuntimeException('Invalid Ed25519 private key length after potential seed expansion.');
        }

        $this->ed25519SecretKey = $decodedKey;

        $keyId = trim($keyId);
        if ($keyId === '') {
            throw new \InvalidArgumentException('Key ID cannot be empty.');
        }
        $this->assertNoNewlines($keyId, 'Key ID');

        $signatureAgent = trim($signatureAgent);
        $signatureAgentParts = parse_url($signatureAgent);
        if ($signatureAgentParts === false || !isset($signatureAgentParts['scheme'], $signatureAgentParts['host'])) {
            throw new \InvalidArgumentException('Signature agent must be a valid absolute URL.');
        }
        if (strtolower($signatureAgentParts['scheme']) !== 'https') {
            throw new \InvalidArgumentException('Signature agent URL must use https.');
        }
        $this->assertNoNewlines($signatureAgent, 'Signature agent');

        $tag = trim($tag);
        if ($tag === '') {
            throw new \InvalidArgumentException('Tag cannot be empty.');
        }
        $this->assertNoNewlines($tag, 'Tag');

        if ($expiresInSeconds <= 0) {
            throw new \InvalidArgumentException('expiresInSeconds must be greater than zero.');
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
                'keyid=' . $this->encodeStructuredFieldString($this->keyId),
                'alg="' . self::SIGNATURE_ALG . '"',
                'tag=' . $this->encodeStructuredFieldString($this->tag),
            ];

            $signatureParamsValue = implode(' ', $signatureInputParams);
            $signatureInputString = 'sig=(' . $signatureParamsValue . ')';

            $signatureBase = $this->createSignatureBase($request, $signatureParamsValue);
            $signature = $this->sign($signatureBase);

            $request = $request->withHeader('Signature-Agent', $this->signatureAgent)
                               ->withHeader('Signature-Input', $signatureInputString)
                               ->withHeader('Signature', 'sig=' . base64_encode($signature));

            return $handler($request, $options);
        };
    }

    private function createSignatureBase(RequestInterface $request, string $signatureParamsValue): string
    {
        $authority = $request->getUri()->getAuthority();
        if ($authority === '') {
            throw new \InvalidArgumentException('Request URI must contain an authority for signing.');
        }

        $coveredComponents = [
            '"@authority"' => $authority,
            '"signature-agent"' => $this->signatureAgent,
        ];

        $baseStringLines = [];
        foreach ($coveredComponents as $name => $value) {
            $baseStringLines[] = $name . ': ' . $value;
        }
        $baseStringLines[] = '"@signature-params": ' . $signatureParamsValue;

        return implode("\n", $baseStringLines);
    }

    private function sign(string $data): string
    {
        if ($this->ed25519SecretKey === '') {
            throw new \RuntimeException('Ed25519 private key cannot be empty.');
        }

        try {
            $signature = sodium_crypto_sign_detached($data, $this->ed25519SecretKey);
        } catch (\SodiumException $e) {
            throw new \RuntimeException('Ed25519 signing failed: ' . $e->getMessage(), 0, $e);
        }

        return $signature;
    }

    private function normalizeKeyInput(string $input): string
    {
        $normalized = preg_replace('/\s+/', '', $input);
        if ($normalized === null) {
            throw new \RuntimeException('Failed to normalize private key input.');
        }

        return trim($normalized);
    }

    private function encodeStructuredFieldString(string $value): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
    }

    private function assertNoNewlines(string $value, string $fieldName): void
    {
        if (preg_match('/[\r\n]/', $value) === 1) {
            throw new \InvalidArgumentException($fieldName . ' cannot contain CR/LF characters.');
        }
    }
}
