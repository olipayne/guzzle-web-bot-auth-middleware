<?php

declare(strict_types=1);

namespace Olipayne\GuzzleWebBotAuth\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Olipayne\GuzzleWebBotAuth\WebBotAuthMiddleware;
use PHPUnit\Framework\TestCase;

class WebBotAuthIntegrationTest extends TestCase
{
    private string $debugUrl = 'https://http-message-signatures-example.research.cloudflare.com/debug';

    /**
     * Helper to generate Ed25519 keys and kid for testing.
     * Returns [base64SecretKey, kid]
     */
    private function generateTestKeys(): array
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium extension is not available.');
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
        $canonicalJson = json_encode($jwkMembers, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $hash = hash('sha256', $canonicalJson, true);
        $kid = rtrim(strtr(base64_encode($hash), '+/', '-_'), '=');

        return [$base64SecretKey, $kid];
    }

    public function testRequestToCloudflareDebugEndpointHasSignatureHeaders()
    {
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium extension is not available.');
        }

        [$base64SecretKey, $kid] = $this->generateTestKeys();
        $signatureAgentUrl = 'https://example.com/.well-known/http-message-signatures-directory'; // Dummy URL for this test

        $stack = HandlerStack::create();
        $middleware = new WebBotAuthMiddleware(
            $base64SecretKey,
            $kid,
            $signatureAgentUrl
        );
        $stack->push($middleware);
        $client = new Client(['handler' => $stack]);

        try {
            $response = $client->request('GET', $this->debugUrl);
            $this->assertEquals(200, $response->getStatusCode());

            $bodyContents = $response->getBody()->getContents();
            
            // Parse plain text headers
            $receivedHeaders = [];
            $lines = explode("\n", trim($bodyContents));
            foreach ($lines as $line) {
                if (strpos($line, ':') !== false) {
                    [$name, $value] = explode(':', $line, 2);
                    $receivedHeaders[strtolower(trim($name))] = trim($value);
                }
            }

            $this->assertNotEmpty($receivedHeaders, 'Could not parse any headers from the response body.');

            // Check for our signature headers
            $this->assertArrayHasKey('signature-agent', $receivedHeaders);
            $this->assertEquals($signatureAgentUrl, $receivedHeaders['signature-agent']);

            $this->assertArrayHasKey('signature-input', $receivedHeaders);
            $this->assertStringStartsWith('sig=(', $receivedHeaders['signature-input']);
            $this->assertStringContainsString('("@authority" "signature-agent")', $receivedHeaders['signature-input']);
            $this->assertStringContainsString('created=', $receivedHeaders['signature-input']);
            $this->assertStringContainsString('expires=', $receivedHeaders['signature-input']);
            $this->assertStringContainsString('keyid="' . $kid . '"', $receivedHeaders['signature-input']);
            $this->assertStringContainsString('alg="ed25519"', $receivedHeaders['signature-input']);
            $this->assertStringContainsString('tag="web-bot-auth"', $receivedHeaders['signature-input']);
            
            $this->assertArrayHasKey('signature', $receivedHeaders);
            $this->assertStringStartsWith('sig=', $receivedHeaders['signature']);
            // Validate base64 encoding of the signature value itself
            $signatureValue = substr($receivedHeaders['signature'], 4); // remove "sig="
            $this->assertTrue((bool)preg_match('/^[a-zA-Z0-9\+\/\=]+$/', $signatureValue), 'Signature value is not valid base64.');
            $this->assertNotEmpty(base64_decode($signatureValue, true), 'Signature value is not valid base64 (strict decode failed).');

        } catch (\GuzzleHttp\Exception\RequestException $e) {
            $this->fail("Request to debug endpoint failed: " . $e->getMessage());
        }
    }
} 
