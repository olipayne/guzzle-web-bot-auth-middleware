<?php

declare(strict_types=1);

namespace Olipayne\GuzzleWebBotAuth\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Olipayne\GuzzleWebBotAuth\WebBotAuthMiddleware;
use PHPUnit\Framework\TestCase;

class WebBotAuthIntegrationTest extends TestCase
{
    private string $verificationUrl = 'https://crawltest.com/cdn-cgi/web-bot-auth';

    /**
     * Helper to generate Ed25519 keys and kid for testing.
     * Returns [base64SecretKey, kid].
     *
     * @return array{string, string}
     */
    private function generateTestKeys(): array
    {
        if (!extension_loaded('sodium')) {
            self::markTestSkipped('Libsodium extension is not available.');
        }

        $keypair = sodium_crypto_sign_keypair();
        $secretKey = sodium_crypto_sign_secretkey($keypair);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        $base64SecretKey = base64_encode($secretKey);

        // Calculate kid (JWK thumbprint of the public key)
        $x_b64url = rtrim(strtr(base64_encode($publicKey), '+/', '-_'), '=');
        $jwkMembers = [
            'crv' => 'Ed25519',
            'kty' => 'OKP',
            'x'   => $x_b64url,
        ];
        ksort($jwkMembers);
        $canonicalJson = json_encode(
            $jwkMembers,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );
        $hash = hash('sha256', $canonicalJson, true);
        $kid = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');

        return [$base64SecretKey, $kid];
    }

    public function testCloudflareAcceptsLegacyWireFormatAsWellFormed(): void
    {
        if (!extension_loaded('sodium')) {
            self::markTestSkipped('Libsodium extension is not available.');
        }

        [$base64SecretKey, $kid] = $this->generateTestKeys();
        $signatureAgentUrl = 'https://example.com/.well-known/http-message-signatures-directory';

        $stack = HandlerStack::create();
        $middleware = new WebBotAuthMiddleware(
            $base64SecretKey,
            $kid,
            $signatureAgentUrl,
            'web-bot-auth',
            300,
            'sig',
            'cloudflare_legacy'
        );
        $stack->push($middleware);
        $client = new Client(['handler' => $stack, 'http_errors' => false]);

        try {
            $response = $client->request('GET', $this->verificationUrl);
            self::assertSame(
                401,
                $response->getStatusCode(),
                'Cloudflare returns 400 for malformed signatures and 401 for a well-formed signature with an unknown key.'
            );

        } catch (\GuzzleHttp\Exception\RequestException $e) {
            self::fail('Request to Cloudflare verification endpoint failed: ' . $e->getMessage());
        }
    }
}
