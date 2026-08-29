<?php

declare(strict_types=1);

namespace Olipayne\GuzzleWebBotAuth\Tests;

use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Olipayne\GuzzleWebBotAuth\WebBotAuthMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

class WebBotAuthMiddlewareTest extends TestCase
{
    private const CREATED = 1700000000;

    private string $validBase64Ed25519Seed;
    private string $validBase64Ed25519SecretKey;
    private string $validPublicKey;
    private string $validKeyId;
    private string $validSignatureAgent = 'https://agent.example';

    protected function setUp(): void
    {
        parent::setUp();
        if (!extension_loaded('sodium')) {
            self::markTestSkipped('Libsodium extension is required for these tests.');
        }

        $seed = str_repeat("\0", SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $keyPair = sodium_crypto_sign_seed_keypair($seed);
        $this->validBase64Ed25519Seed = base64_encode($seed);
        $this->validBase64Ed25519SecretKey = base64_encode(sodium_crypto_sign_secretkey($keyPair));
        $this->validPublicKey = sodium_crypto_sign_publickey($keyPair);
        $this->validKeyId = $this->calculateJwkThumbprint($this->validPublicKey);
    }

    public function testConstructorAcceptsSeedAndSecretKey(): void
    {
        self::assertInstanceOf(WebBotAuthMiddleware::class, $this->createMiddleware());
        self::assertInstanceOf(
            WebBotAuthMiddleware::class,
            $this->createMiddleware($this->validBase64Ed25519SecretKey)
        );
    }

    public function testConstructorReadsAKeyFileContainingWhitespace(): void
    {
        $keyFilePath = tempnam(sys_get_temp_dir(), 'web_bot_auth_key_');
        self::assertNotFalse($keyFilePath);
        self::assertNotFalse(file_put_contents($keyFilePath, $this->validBase64Ed25519Seed . "\n"));

        try {
            self::assertInstanceOf(WebBotAuthMiddleware::class, $this->createMiddleware($keyFilePath));
        } finally {
            unlink($keyFilePath);
        }
    }

    public function testConstructorRejectsInvalidPrivateKeyInput(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Private key does not appear to be a valid base64 encoded string.');

        $this->createMiddleware('this-is-not-base64!!!');
    }

    public function testConstructorRejectsPrivateKeyWithWrongLength(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decoded Ed25519 private key must be either');

        $this->createMiddleware(base64_encode(random_bytes(16)));
    }

    public function testConstructorRequiresJwkThumbprintKeyId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Key ID must be an unpadded base64url SHA-256 JWK Thumbprint.');

        new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            'not-a-thumbprint',
            $this->validSignatureAgent
        );
    }

    public function testConstructorRejectsThumbprintForAnotherKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Key ID must be the JWK Thumbprint of the configured Ed25519 private key.');

        new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            str_repeat('A', 43),
            $this->validSignatureAgent
        );
    }

    /** @dataProvider invalidSignatureAgentProvider */
    public function testConstructorRejectsInvalidSignatureAgent(string $url, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new WebBotAuthMiddleware($this->validBase64Ed25519Seed, $this->validKeyId, $url);
    }

    /** @return array<string, array{string, string}> */
    public function invalidSignatureAgentProvider(): array
    {
        return [
            'not absolute' => ['not-a-url', 'Signature agent must be a valid absolute URL.'],
            'not HTTPS' => ['http://agent.example', 'Signature agent URL must use https.'],
            'userinfo' => ['https://user@agent.example', 'cannot contain user information'],
            'fragment' => ['https://agent.example/#key', 'cannot contain user information or a fragment'],
            'directory path' => ['https://agent.example/keys.json', 'Directory discovery requires an HTTPS origin'],
            'directory query' => ['https://agent.example?set=1', 'Directory discovery requires an HTTPS origin'],
        ];
    }

    public function testConstructorRejectsUnknownDiscoveryType(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Discovery type must be directory, jwks_uri, cimd, or cloudflare_legacy.');

        $this->createMiddleware(null, 'sig1', 'unknown');
    }

    public function testConstructorRejectsInvalidSignatureLabel(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Signature label must be a valid Structured Fields dictionary key.');

        $this->createMiddleware(null, 'Invalid Label');
    }

    public function testConstructorRejectsEmptyTag(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Tag cannot be empty.');

        new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $this->validSignatureAgent,
            '   '
        );
    }

    public function testConstructorRejectsNonPositiveExpiry(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('expiresInSeconds must be greater than zero.');

        new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $this->validSignatureAgent,
            'web-bot-auth',
            0
        );
    }

    public function testRetainsCustomTagAndLongExpiryForBackwardsCompatibility(): void
    {
        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $this->validSignatureAgent,
            'custom-profile',
            86401,
            'sig',
            'directory',
            static fn (): int => self::CREATED
        );

        $signedRequest = $this->signRequest($middleware, new Request('GET', 'https://origin.example'));

        self::assertStringContainsString(';expires=1700086401', $signedRequest->getHeaderLine('Signature-Input'));
        self::assertStringContainsString(';tag="custom-profile"', $signedRequest->getHeaderLine('Signature-Input'));
    }

    public function testProducesCurrentDraftStructuredFieldsAndVerifiableSignature(): void
    {
        $request = new Request('POST', 'https://origin.example:8443/path/to/resource?b=2&a=1');
        $signedRequest = $this->signRequest($this->createMiddleware(), $request);

        $expectedSignatureInput = 'sig=("@authority" "@method" "@path" "@query" "signature-agent";key="sig")'
            . ';created=1700000000;expires=1700000300'
            . ';keyid="' . $this->validKeyId . '";alg="ed25519";tag="web-bot-auth"';

        self::assertSame('sig="https://agent.example"', $signedRequest->getHeaderLine('Signature-Agent'));
        self::assertSame($expectedSignatureInput, $signedRequest->getHeaderLine('Signature-Input'));

        $signatureHeader = $signedRequest->getHeaderLine('Signature');
        self::assertMatchesRegularExpression('/^sig=:[A-Za-z0-9+\/]+={0,2}:$/', $signatureHeader);
        $signature = base64_decode(substr($signatureHeader, 5, -1), true);
        if ($signature === false || $signature === '' || $this->validPublicKey === '') {
            self::fail('Signature and public key must be non-empty byte strings.');
        }

        $signatureBase = implode("\n", [
            '"@authority": origin.example:8443',
            '"@method": POST',
            '"@path": /path/to/resource',
            '"@query": ?b=2&a=1',
            '"signature-agent";key="sig": "https://agent.example"',
            '"@signature-params": ' . substr($expectedSignatureInput, 4),
        ]);

        self::assertTrue(sodium_crypto_sign_verify_detached($signature, $signatureBase, $this->validPublicKey));
    }

    public function testNormalizesLegacyWellKnownDirectoryUrlToCurrentOriginForm(): void
    {
        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            'https://AGENT.example:443/.well-known/http-message-signatures-directory',
            'web-bot-auth',
            300,
            'sig',
            'directory',
            static fn (): int => self::CREATED
        );

        $signedRequest = $this->signRequest($middleware, new Request('GET', 'https://origin.example'));

        self::assertSame('sig="https://agent.example"', $signedRequest->getHeaderLine('Signature-Agent'));
        self::assertStringContainsString('"@path" "@query"', $signedRequest->getHeaderLine('Signature-Input'));
    }

    public function testCloudflareLegacyDiscoveryUsesExplicitBareStringForm(): void
    {
        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            'https://agent.example/.well-known/http-message-signatures-directory',
            'web-bot-auth',
            300,
            'sig',
            'cloudflare_legacy',
            static fn (): int => self::CREATED
        );

        $signedRequest = $this->signRequest($middleware, new Request('GET', 'https://origin.example'));

        self::assertSame(
            '"https://agent.example/.well-known/http-message-signatures-directory"',
            $signedRequest->getHeaderLine('Signature-Agent')
        );
        self::assertStringContainsString('"signature-agent")', $signedRequest->getHeaderLine('Signature-Input'));
        self::assertStringNotContainsString('"signature-agent";key=', $signedRequest->getHeaderLine('Signature-Input'));
    }

    public function testCloudflareLegacyDiscoveryRequiresWellKnownUrl(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cloudflare legacy discovery requires the full HTTPS well-known directory URL');

        $this->createMiddleware(null, 'sig', 'cloudflare_legacy');
    }

    public function testCoversAnExistingContentDigest(): void
    {
        $request = new Request(
            'POST',
            'https://origin.example/items',
            ['Content-Digest' => 'sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:'],
            'hello'
        );

        $signedRequest = $this->signRequest($this->createMiddleware(), $request);

        self::assertStringContainsString(
            '"@query" "content-digest" "signature-agent";key="sig"',
            $signedRequest->getHeaderLine('Signature-Input')
        );
    }

    /** @dataProvider nonDirectoryDiscoveryProvider */
    public function testSerializesExplicitDiscoveryType(string $url, string $type): void
    {
        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $url,
            'web-bot-auth',
            300,
            'agent-key',
            $type,
            static fn (): int => self::CREATED
        );

        $signedRequest = $this->signRequest($middleware, new Request('GET', 'https://origin.example/'));
        $member = '"' . $url . '";type=' . $type;

        self::assertSame('agent-key=' . $member, $signedRequest->getHeaderLine('Signature-Agent'));
        self::assertStringContainsString(
            '"signature-agent";key="agent-key"',
            $signedRequest->getHeaderLine('Signature-Input')
        );
    }

    /** @return array<string, array{string, string}> */
    public function nonDirectoryDiscoveryProvider(): array
    {
        return [
            'direct JWKS' => ['https://agent.example/keys.json', 'jwks_uri'],
            'client metadata document' => ['https://agent.example/client.json', 'cimd'],
        ];
    }

    public function testRejectsRelativeRequestUri(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Request URI must contain an authority for signing.');

        $this->signRequest($this->createMiddleware(), new Request('GET', '/relative-path'));
    }

    public function testRejectsRequestUriUserInfo(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Request URI cannot contain user information for signing.');

        $this->signRequest($this->createMiddleware(), new Request('GET', 'https://user@origin.example/path'));
    }

    public function testRejectsClockReturningNonInteger(): void
    {
        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $this->validSignatureAgent,
            'web-bot-auth',
            300,
            'sig1',
            'directory',
            static fn (): string => '1700000000'
        );

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Clock callable must return an integer Unix timestamp.');

        $this->signRequest($middleware, new Request('GET', 'https://origin.example'));
    }

    private function createMiddleware(
        ?string $privateKey = null,
        string $signatureLabel = 'sig',
        string $discoveryType = 'directory'
    ): WebBotAuthMiddleware {
        return new WebBotAuthMiddleware(
            $privateKey ?? $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $this->validSignatureAgent,
            'web-bot-auth',
            300,
            $signatureLabel,
            $discoveryType,
            static fn (): int => self::CREATED
        );
    }

    private function signRequest(WebBotAuthMiddleware $middleware, RequestInterface $request): RequestInterface
    {
        $signedRequest = null;
        $handler = static function (RequestInterface $handledRequest) use (&$signedRequest): FulfilledPromise {
            $signedRequest = $handledRequest;

            return new FulfilledPromise(new Response());
        };

        $middleware($handler)($request, [])->wait();
        self::assertInstanceOf(RequestInterface::class, $signedRequest);

        return $signedRequest;
    }

    private function calculateJwkThumbprint(string $publicKey): string
    {
        $x = rtrim(strtr(base64_encode($publicKey), '+/', '-_'), '=');
        $canonicalJwk = json_encode(['crv' => 'Ed25519', 'kty' => 'OKP', 'x' => $x]);
        self::assertNotFalse($canonicalJwk);

        return rtrim(strtr(base64_encode(hash('sha256', $canonicalJwk, true)), '+/', '-_'), '=');
    }
}
