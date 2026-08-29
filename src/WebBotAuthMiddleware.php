<?php

declare(strict_types=1);

namespace Olipayne\GuzzleWebBotAuth;

use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\RequestInterface;

class WebBotAuthMiddleware
{
    private const SIGNATURE_ALG = 'ed25519';
    private const PROFILE_TAG = 'web-bot-auth';
    private const WELL_KNOWN_DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';

    private string $ed25519SecretKey;
    private string $keyId; // JWK Thumbprint of the Ed25519 public key
    private string $signatureAgentMember;
    private string $signatureLabel;
    private string $tag;
    private int $expiresInSeconds;
    private bool $usesCloudflareLegacySignatureAgent;

    /** @var \Closure(): mixed */
    private \Closure $clock;

    public function __construct(
        string $base64Ed25519PrivateKeyOrPath,
        string $keyId,
        string $signatureAgent,
        string $tag = self::PROFILE_TAG,
        int $expiresInSeconds = 300,
        string $signatureLabel = 'sig',
        string $discoveryType = 'directory',
        ?callable $clock = null
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
        if (preg_match('/^[A-Za-z0-9_-]{43}$/', $keyId) !== 1) {
            throw new \InvalidArgumentException('Key ID must be an unpadded base64url SHA-256 JWK Thumbprint.');
        }
        if (!hash_equals($this->calculateJwkThumbprint($decodedKey), $keyId)) {
            throw new \InvalidArgumentException('Key ID must be the JWK Thumbprint of the configured Ed25519 private key.');
        }

        $signatureAgent = trim($signatureAgent);
        $signatureAgentParts = parse_url($signatureAgent);
        if ($signatureAgentParts === false || !isset($signatureAgentParts['scheme'], $signatureAgentParts['host'])) {
            throw new \InvalidArgumentException('Signature agent must be a valid absolute URL.');
        }
        if (strtolower($signatureAgentParts['scheme']) !== 'https') {
            throw new \InvalidArgumentException('Signature agent URL must use https.');
        }
        $this->assertNoNewlines($signatureAgent, 'Signature agent');
        $this->assertStructuredFieldString($signatureAgent, 'Signature agent');
        if (isset($signatureAgentParts['user']) || isset($signatureAgentParts['pass']) || isset($signatureAgentParts['fragment'])) {
            throw new \InvalidArgumentException('Signature agent URL cannot contain user information or a fragment.');
        }

        $signatureLabel = trim($signatureLabel);
        if (preg_match('/^[a-z*][a-z0-9_.*-]*$/', $signatureLabel) !== 1) {
            throw new \InvalidArgumentException('Signature label must be a valid Structured Fields dictionary key.');
        }

        if (!in_array($discoveryType, ['directory', 'jwks_uri', 'cimd', 'cloudflare_legacy'], true)) {
            throw new \InvalidArgumentException('Discovery type must be directory, jwks_uri, cimd, or cloudflare_legacy.');
        }

        if ($discoveryType === 'directory') {
            $path = $signatureAgentParts['path'] ?? '';
            if (!in_array($path, ['', '/', self::WELL_KNOWN_DIRECTORY_PATH], true) || isset($signatureAgentParts['query'])) {
                throw new \InvalidArgumentException(
                    'Directory discovery requires an HTTPS origin (or the legacy well-known directory URL) without a query.'
                );
            }
            $signatureAgent = $this->normalizeDirectoryOrigin($signatureAgentParts);
        } elseif ($discoveryType === 'cloudflare_legacy') {
            $path = $signatureAgentParts['path'] ?? '';
            if ($path !== self::WELL_KNOWN_DIRECTORY_PATH || isset($signatureAgentParts['query'])) {
                throw new \InvalidArgumentException(
                    'Cloudflare legacy discovery requires the full HTTPS well-known directory URL without a query.'
                );
            }
        }

        $tag = trim($tag);
        $this->assertNoNewlines($tag, 'Tag');
        $this->assertStructuredFieldString($tag, 'Tag');
        if ($tag === '') {
            throw new \InvalidArgumentException('Tag cannot be empty.');
        }

        if ($expiresInSeconds <= 0) {
            throw new \InvalidArgumentException('expiresInSeconds must be greater than zero.');
        }

        $this->keyId = $keyId;
        $this->signatureLabel = $signatureLabel;
        $this->tag = $tag;
        $this->signatureAgentMember = $this->encodeStructuredFieldString($signatureAgent);
        $this->usesCloudflareLegacySignatureAgent = $discoveryType === 'cloudflare_legacy';
        if (!in_array($discoveryType, ['directory', 'cloudflare_legacy'], true)) {
            $this->signatureAgentMember .= ';type=' . $discoveryType;
        }
        $this->expiresInSeconds = $expiresInSeconds;
        $this->clock = $clock === null ? static fn (): int => time() : \Closure::fromCallable($clock);
    }

    public function __invoke(callable $handler): callable
    {
        return function (RequestInterface $request, array $options) use ($handler): PromiseInterface {
            $created = ($this->clock)();
            if (!is_int($created)) {
                throw new \RuntimeException('Clock callable must return an integer Unix timestamp.');
            }
            $expires = $created + $this->expiresInSeconds;
            $signatureAgentComponent = '"signature-agent"';
            if (!$this->usesCloudflareLegacySignatureAgent) {
                $signatureAgentComponent .= ';key=' . $this->encodeStructuredFieldString($this->signatureLabel);
            }
            $coveredComponents = $this->createCoveredComponents($request, $signatureAgentComponent);
            $coveredComponentList = '(' . implode(' ', array_keys($coveredComponents)) . ')';

            $signatureInputParams = [
                ';created=' . $created,
                ';expires=' . $expires,
                ';keyid=' . $this->encodeStructuredFieldString($this->keyId),
                ';alg="' . self::SIGNATURE_ALG . '"',
                ';tag=' . $this->encodeStructuredFieldString($this->tag),
            ];

            $signatureParamsValue = $coveredComponentList . implode('', $signatureInputParams);
            $signatureInputString = $this->signatureLabel . '=' . $signatureParamsValue;

            $signatureBase = $this->createSignatureBase($coveredComponents, $signatureParamsValue);
            $signature = $this->sign($signatureBase);

            $request = $request->withHeader(
                'Signature-Agent',
                $this->usesCloudflareLegacySignatureAgent
                    ? $this->signatureAgentMember
                    : $this->signatureLabel . '=' . $this->signatureAgentMember
            )
                               ->withHeader('Signature-Input', $signatureInputString)
                               ->withHeader(
                                   'Signature',
                                   $this->signatureLabel . '=:' . base64_encode($signature) . ':'
                               );

            return $handler($request, $options);
        };
    }

    /**
     * @return array<string, string>
     */
    private function createCoveredComponents(RequestInterface $request, string $signatureAgentComponent): array
    {
        $uri = $request->getUri();
        if ($uri->getUserInfo() !== '') {
            throw new \InvalidArgumentException('Request URI cannot contain user information for signing.');
        }

        $host = strtolower($uri->getHost());
        if ($host === '') {
            throw new \InvalidArgumentException('Request URI must contain an authority for signing.');
        }
        if (strpos($host, ':') !== false && $host[0] !== '[') {
            $host = '[' . $host . ']';
        }
        $authority = $host . ($uri->getPort() === null ? '' : ':' . $uri->getPort());

        $path = $uri->getPath();
        if ($path === '') {
            $path = '/';
        }

        $query = '?' . $uri->getQuery();
        $coveredComponents = [
            '"@authority"' => $authority,
            '"@method"' => $request->getMethod(),
            '"@path"' => $path,
            '"@query"' => $query,
        ];

        if ($request->hasHeader('Content-Digest')) {
            $coveredComponents['"content-digest"'] = $request->getHeaderLine('Content-Digest');
        }

        $coveredComponents[$signatureAgentComponent] = $this->signatureAgentMember;

        return $coveredComponents;
    }

    /**
     * @param array<string, string> $coveredComponents
     */
    private function createSignatureBase(array $coveredComponents, string $signatureParamsValue): string
    {
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

    private function calculateJwkThumbprint(string $secretKey): string
    {
        if ($secretKey === '') {
            throw new \RuntimeException('Ed25519 private key cannot be empty.');
        }

        $publicKey = sodium_crypto_sign_publickey_from_secretkey($secretKey);
        $x = rtrim(strtr(base64_encode($publicKey), '+/', '-_'), '=');
        $canonicalJwk = '{"crv":"Ed25519","kty":"OKP","x":"' . $x . '"}';

        return rtrim(strtr(base64_encode(hash('sha256', $canonicalJwk, true)), '+/', '-_'), '=');
    }

    /**
     * @param array<string, int|string> $parts
     */
    private function normalizeDirectoryOrigin(array $parts): string
    {
        $host = strtolower((string)$parts['host']);
        if (strpos($host, ':') !== false && $host[0] !== '[') {
            $host = '[' . $host . ']';
        }

        $port = isset($parts['port']) && $parts['port'] !== 443 ? ':' . $parts['port'] : '';

        return 'https://' . $host . $port;
    }

    private function assertStructuredFieldString(string $value, string $fieldName): void
    {
        if (preg_match('/[^\x20-\x7E]/', $value) === 1) {
            throw new \InvalidArgumentException($fieldName . ' must contain only printable ASCII characters.');
        }
    }

    private function assertNoNewlines(string $value, string $fieldName): void
    {
        if (preg_match('/[\r\n]/', $value) === 1) {
            throw new \InvalidArgumentException($fieldName . ' cannot contain CR/LF characters.');
        }
    }
}
