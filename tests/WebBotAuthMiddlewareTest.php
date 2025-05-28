<?php

namespace Olipayne\GuzzleWebBotAuth\Tests;

use GuzzleHttp\Psr7\Request;
use Psr\Http\Message\RequestInterface;
use Olipayne\GuzzleWebBotAuth\WebBotAuthMiddleware;
use PHPUnit\Framework\TestCase;

class WebBotAuthMiddlewareTest extends TestCase
{
    private string $validBase64Ed25519Seed = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; // 32 bytes of nulls, base64 encoded
    private string $validBase64Ed25519SecretKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='; // 64 bytes of nulls, base64 encoded
    private string $validKeyId = 'test-key-id';
    private string $validSignatureAgent = 'https://example.com/.well-known/jwks.json';

    protected function setUp(): void
    {
        parent::setUp();
        if (!extension_loaded('sodium')) {
            $this->markTestSkipped('Libsodium extension is required for these tests.');
        }
    }

    public function testConstructorWithValidDirectPrivateKeyString()
    {
        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $this->validSignatureAgent
        );
        $this->assertInstanceOf(WebBotAuthMiddleware::class, $middleware);
    }

    public function testConstructorWithValidPrivateKeyFile()
    {
        $keyFilePath = sys_get_temp_dir() . '/' . uniqid('test_pk_') . '.key';
        file_put_contents($keyFilePath, $this->validBase64Ed25519Seed);

        $middleware = new WebBotAuthMiddleware(
            $keyFilePath,
            $this->validKeyId,
            $this->validSignatureAgent
        );
        $this->assertInstanceOf(WebBotAuthMiddleware::class, $middleware);

        unlink($keyFilePath); // Clean up
    }

    public function testConstructorWithInvalidPrivateKeyFileThrowsException()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Private key does not appear to be a valid base64 encoded string.');
        new WebBotAuthMiddleware(
            '/path/to/nonexistent/key.pem',
            $this->validKeyId,
            $this->validSignatureAgent
        );
    }

    public function testConstructorWithInvalidBase64PrivateKeyStringThrowsException()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Private key does not appear to be a valid base64 encoded string.');
        new WebBotAuthMiddleware(
            'this-is-not-base64!!!',
            $this->validKeyId,
            $this->validSignatureAgent
        );
    }

    public function testConstructorWithIncorrectKeyLengthPrivateKeyStringThrowsException()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Decoded Ed25519 private key must be either'); // Partial message
        $shortKey = base64_encode(random_bytes(16)); // 16 bytes, too short
        new WebBotAuthMiddleware(
            $shortKey,
            $this->validKeyId,
            $this->validSignatureAgent
        );
    }

    private function getDummyRequest(string $method = 'GET', string $url = 'https://example.com/path'): Request
    {
        return new Request($method, $url);
    }

    public function testInvokeAddsSignatureHeaders()
    {
        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $this->validSignatureAgent
        );

        $request = $this->getDummyRequest();
        $options = [];

        // Mock the handler
        $handler = function (RequestInterface $req, array $opt) {
            // Assertions on the request modified by the middleware
            $this->assertTrue($req->hasHeader('Signature-Agent'));
            $this->assertEquals($this->validSignatureAgent, $req->getHeaderLine('Signature-Agent'));

            $this->assertTrue($req->hasHeader('Signature-Input'));
            $signatureInput = $req->getHeaderLine('Signature-Input');
            $this->assertStringStartsWith('sig=(', $signatureInput);
            $this->assertStringContainsString('keyid="' . $this->validKeyId . '"', $signatureInput);
            $this->assertStringContainsString('alg="ed25519"', $signatureInput);
            $this->assertStringContainsString('tag="web-bot-auth"', $signatureInput);
            $this->assertStringContainsString('created=', $signatureInput);
            $this->assertStringContainsString('expires=', $signatureInput);
            $this->assertStringContainsString('("@authority" "signature-agent")', $signatureInput);

            $this->assertTrue($req->hasHeader('Signature'));
            $this->assertStringStartsWith('sig=', $req->getHeaderLine('Signature'));
            
            // Return a dummy promise
            return new \GuzzleHttp\Promise\FulfilledPromise(new \GuzzleHttp\Psr7\Response());
        };

        $fn = $middleware($handler);
        $fn($request, $options)->wait(); // Execute and wait for promise to resolve
    }

    public function testInvokeWithCustomTagAndExpires()
    {
        $customTag = 'my-custom-bot';
        $customExpires = 60; // 1 minute

        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519Seed,
            $this->validKeyId,
            $this->validSignatureAgent,
            $customTag,
            $customExpires
        );

        $request = $this->getDummyRequest();
        $options = [];
        $startTime = time();

        $handler = function (RequestInterface $req, array $opt) use ($customTag, $customExpires, $startTime) {
            $this->assertTrue($req->hasHeader('Signature-Input'));
            $signatureInput = $req->getHeaderLine('Signature-Input');
            $this->assertStringContainsString('tag="' . $customTag . '"', $signatureInput);
            
            // Check expires calculation
            preg_match('/created=(\d+)/', $signatureInput, $createdMatches);
            preg_match('/expires=(\d+)/', $signatureInput, $expiresMatches);
            $this->assertCount(2, $createdMatches);
            $this->assertCount(2, $expiresMatches);
            $created = (int)$createdMatches[1];
            $expires = (int)$expiresMatches[1];

            // Allow a small delta for time discrepancies during test run
            $this->assertGreaterThanOrEqual($startTime, $created);
            $this->assertLessThanOrEqual($startTime + 5, $created); // Allow 5s skew for created
            $this->assertEquals($created + $customExpires, $expires);
            
            return new \GuzzleHttp\Promise\FulfilledPromise(new \GuzzleHttp\Psr7\Response());
        };

        $fn = $middleware($handler);
        $fn($request, $options)->wait();
    }

    public function testInvokeWithFullSecretKeyGeneratesSignature()
    {
        $middleware = new WebBotAuthMiddleware(
            $this->validBase64Ed25519SecretKey, // Using the 64-byte key
            $this->validKeyId,
            $this->validSignatureAgent
        );

        $request = $this->getDummyRequest();
        $options = [];

        $handler = function (RequestInterface $req, array $opt) {
            $this->assertTrue($req->hasHeader('Signature'));
            $signatureHeader = $req->getHeaderLine('Signature');
            $this->assertStringStartsWith('sig=', $signatureHeader);
            $signatureValue = substr($signatureHeader, 4);
            $this->assertNotEmpty($signatureValue);
            $this->assertTrue((bool)preg_match('/^[a-zA-Z0-9\+\/\=]+$/', $signatureValue), 'Signature value is not valid base64.');
            $this->assertNotEmpty(base64_decode($signatureValue, true), 'Signature value is not valid base64 (strict decode failed).');
            return new \GuzzleHttp\Promise\FulfilledPromise(new \GuzzleHttp\Psr7\Response());
        };

        $fn = $middleware($handler);
        $fn($request, $options)->wait();
    }

    // TODO: Add more tests here
} 