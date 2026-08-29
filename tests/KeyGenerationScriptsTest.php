<?php

declare(strict_types=1);

namespace Olipayne\GuzzleWebBotAuth\Tests;

use PHPUnit\Framework\TestCase;

class KeyGenerationScriptsTest extends TestCase
{
    public function testGenerateJwkUsesRegisteredHttpSignatureAlgorithmName(): void
    {
        $seed = str_repeat("\0", SODIUM_CRYPTO_SIGN_SEEDBYTES);
        $keyPair = sodium_crypto_sign_seed_keypair($seed);
        $publicKey = sodium_crypto_sign_publickey($keyPair);
        $command = escapeshellarg(PHP_BINARY)
            . ' '
            . escapeshellarg(dirname(__DIR__) . '/bin/generate-jwk.php')
            . ' '
            . escapeshellarg(base64_encode($publicKey));

        exec($command, $outputLines, $exitCode);
        $output = implode("\n", $outputLines);

        self::assertSame(0, $exitCode, $output);
        self::assertStringContainsString('"alg": "ed25519"', $output);
        self::assertStringNotContainsString('"alg": "Ed25519"', $output);
        self::assertStringContainsString('"kid": "' . $this->calculateJwkThumbprint($publicKey) . '"', $output);
    }

    public function testGenerateKeysProtectsAndDoesNotPrintPrivateKey(): void
    {
        $temporaryDirectory = sys_get_temp_dir() . '/web-bot-auth-' . bin2hex(random_bytes(6));
        self::assertTrue(mkdir($temporaryDirectory, 0700));

        try {
            $result = $this->runProcess([PHP_BINARY, dirname(__DIR__) . '/bin/generate-keys.php'], $temporaryDirectory);
            $privateKeyPath = $temporaryDirectory . '/ed25519_private.key';
            $publicKeyPath = $temporaryDirectory . '/ed25519_public.key';

            self::assertSame(0, $result['exitCode'], $result['stderr']);
            self::assertFileExists($privateKeyPath);
            self::assertFileExists($publicKeyPath);

            $privateKey = file_get_contents($privateKeyPath);
            if ($privateKey === false) {
                self::fail('Could not read generated private key.');
            }
            self::assertStringNotContainsString($privateKey, $result['stdout']);
            self::assertStringContainsString('not printed; keep this file secret', $result['stdout']);
            self::assertStringNotContainsString('or printed above', $result['stdout']);
            self::assertStringContainsString('"alg": "ed25519"', $result['stdout']);

            if (DIRECTORY_SEPARATOR !== '\\') {
                $permissions = fileperms($privateKeyPath);
                self::assertNotFalse($permissions);
                self::assertSame(0600, $permissions & 0777);
            }
        } finally {
            foreach (['ed25519_private.key', 'ed25519_public.key'] as $filename) {
                $path = $temporaryDirectory . '/' . $filename;
                if (file_exists($path)) {
                    unlink($path);
                }
            }
            rmdir($temporaryDirectory);
        }
    }

    /**
     * @param list<string> $command
     *
     * @return array{exitCode: int, stdout: string, stderr: string}
     */
    private function runProcess(array $command, string $workingDirectory): array
    {
        $pipes = [];
        $process = proc_open(
            $command,
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            $workingDirectory
        );
        if (!is_resource($process)) {
            throw new \RuntimeException('Could not start key generation process.');
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        if ($stdout === false || $stderr === false) {
            throw new \RuntimeException('Could not read key generation process output.');
        }

        return [
            'exitCode' => proc_close($process),
            'stdout' => $stdout,
            'stderr' => $stderr,
        ];
    }

    private function calculateJwkThumbprint(string $publicKey): string
    {
        $x = rtrim(strtr(base64_encode($publicKey), '+/', '-_'), '=');
        $canonicalJwk = json_encode(['crv' => 'Ed25519', 'kty' => 'OKP', 'x' => $x]);
        self::assertNotFalse($canonicalJwk);

        return rtrim(strtr(base64_encode(hash('sha256', $canonicalJwk, true)), '+/', '-_'), '=');
    }
}
