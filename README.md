[![Latest Stable Version](https://img.shields.io/packagist/v/olipayne/guzzle-web-bot-auth-middleware.svg?style=flat-square)](https://packagist.org/packages/olipayne/guzzle-web-bot-auth-middleware)
[![Total Downloads](https://img.shields.io/packagist/dt/olipayne/guzzle-web-bot-auth-middleware.svg?style=flat-square)](https://packagist.org/packages/olipayne/guzzle-web-bot-auth-middleware)
[![License](https://img.shields.io/packagist/l/olipayne/guzzle-web-bot-auth-middleware.svg?style=flat-square)](https://packagist.org/packages/olipayne/guzzle-web-bot-auth-middleware)
[![CI](https://img.shields.io/github/actions/workflow/status/olipayne/guzzle-web-bot-auth-middleware/ci.yml?branch=main&style=flat-square)](https://github.com/olipayne/guzzle-web-bot-auth-middleware/actions/workflows/ci.yml)

# Guzzle Web Bot Auth Middleware

This package signs outbound Guzzle requests with Ed25519 HTTP Message Signatures. It lets an automated client prove continuity of identity without relying only on a spoofable `User-Agent`, changing cloud IP ranges, or a shared secret negotiated with every origin.

The receiving server still decides whether to trust or authorize that identity. A valid signature proves control of a key published by the claimed Signature Agent; it does not prove that the bot is safe or that a request is authorized.

## Standards status

The implementation follows:

- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html) for signature construction and fields.
- [RFC 9651: Structured Field Values for HTTP](https://www.rfc-editor.org/rfc/rfc9651.html), which obsoletes RFC 8941, for field serialization.
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) and [RFC 8037 Appendix A.3](https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.3) for Ed25519 JWK Thumbprints.
- [draft-meunier-webbotauth-httpsig-protocol-02](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/), published 18 August 2026, for the Web Bot Auth profile and key discovery.

RFC 9421 is stable. The Web Bot Auth protocol is an active Standards Track Internet-Draft and can change before it becomes an RFC. The exact draft revision above is therefore part of this package's compatibility contract; Renovate and the scheduled integration test help surface ecosystem drift, but consumers should still review release notes before upgrading.

For each request the middleware currently emits:

```http
Signature-Agent: sig="https://agent.example"
Signature-Input: sig=("@authority" "@method" "@path" "@query" "signature-agent";key="sig");created=1700000000;expires=1700000300;keyid="...";alg="ed25519";tag="web-bot-auth"
Signature: sig=:base64-signature-bytes:
```

Covering the method, path, and query as well as the required authority narrows replay scope. If the request already has a `Content-Digest` field, the middleware covers it too. It does not calculate a digest or buffer request bodies for you.

### Deployment compatibility

[Cloudflare's deployed verifier and public documentation](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/) currently use the older bare-string `Signature-Agent` field, while the current Internet-Draft requires the dictionary form shown above. Use the standards-current `directory` default for new integrations. If a Cloudflare endpoint returns `400` because it has not adopted the current draft yet, select the explicit `cloudflare_legacy` mode as a temporary compatibility bridge:

```php
$middleware = new WebBotAuthMiddleware(
    $privateKey,
    $keyId,
    'https://agent.example/.well-known/http-message-signatures-directory',
    'web-bot-auth',
    300,
    'sig',
    'cloudflare_legacy'
);
```

That mode emits a bare Structured Fields string and covers `"signature-agent"` without the current draft's `key` parameter. It is intentionally opt-in and should be removed from application configuration when the target verifier supports the current draft.

## Requirements

- PHP 7.4 or later with `ext-sodium`.
- Guzzle 7 or 8.

## Installation

```bash
composer require olipayne/guzzle-web-bot-auth-middleware
```

## Generate an Ed25519 key

From your application root:

```bash
php vendor/olipayne/guzzle-web-bot-auth-middleware/bin/generate-keys.php
```

The script creates:

- `ed25519_private.key`, mode `0600`, containing the base64-encoded private key. It is deliberately not printed; keep it out of source control and backups that are not approved for secrets.
- `ed25519_public.key`, containing the base64-encoded public key.
- A public JWK and its unpadded base64url SHA-256 thumbprint (`kid`). The JWK uses the HTTP Message Signatures algorithm name `ed25519`.

To convert an existing raw 32-byte Ed25519 public key encoded as base64:

```bash
php vendor/olipayne/guzzle-web-bot-auth-middleware/bin/generate-jwk.php path/to/ed25519_public.key
```

## Publish the key directory

With the default `directory` discovery type, publish a JWKS at:

```text
https://agent.example/.well-known/http-message-signatures-directory
```

Serve it over HTTPS with `Content-Type: application/http-message-signatures-directory+json`:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "base64url-public-key-without-padding",
      "kid": "base64url-jwk-thumbprint-without-padding",
      "alg": "ed25519",
      "use": "sig"
    }
  ]
}
```

The current draft permits a directly resolved directory without a signed directory response. A signature is still needed when redistributed key material is expected to prove its association with the directory URL. This package signs requests; serving and signing the directory response remains the operator's responsibility.

## Usage

Pass the private key or its file path, the JWK Thumbprint, and the Signature Agent origin:

```php
<?php

require 'vendor/autoload.php';

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use Olipayne\GuzzleWebBotAuth\WebBotAuthMiddleware;

$stack = HandlerStack::create();
$stack->push(new WebBotAuthMiddleware(
    '/run/secrets/ed25519_private.key',
    'YOUR_UNPADDED_BASE64URL_JWK_THUMBPRINT',
    'https://agent.example'
));

$client = new Client(['handler' => $stack]);
$response = $client->get('https://origin.example/api/data');
```

The exact legacy well-known URL is also accepted and normalized to its origin, so existing configuration can migrate without changing the stored value.

### Discovery types and optional settings

Constructor arguments after the three required values are intentionally optional and retain their original positions:

1. `tag` defaults to `web-bot-auth`. A custom value is retained for backwards compatibility but opts the signature out of the Web Bot Auth profile.
2. `expiresInSeconds` defaults to 300. The draft recommends no more than 24 hours; shorter lifetimes reduce replay exposure.
3. `signatureLabel` defaults to `sig`.
4. `discoveryType` defaults to `directory`; current-draft values are `directory`, `jwks_uri`, and `cimd`. The transitional `cloudflare_legacy` value is also available for the deployed compatibility case described above.
5. `clock` is an optional callable for deterministic testing and must return an integer Unix timestamp.

For a direct JWKS URL, select `jwks_uri` explicitly:

```php
$middleware = new WebBotAuthMiddleware(
    $privateKey,
    $keyId,
    'https://agent.example/keys.json',
    'web-bot-auth',
    300,
    'sig',
    'jwks_uri'
);
```

This emits `Signature-Agent: sig="https://agent.example/keys.json";type=jwks_uri` as required by the current draft.

## Upgrading from 1.x

Version 2.0 corrects the RFC 9421 wire format and adopts the current dictionary form of `Signature-Agent`. This is intentionally a major release because verifiers or tests that depended on the old malformed/legacy fields will observe different headers.

The constructor's first five positional arguments remain compatible. The default signature label also remains `sig`. The material changes are:

- `Signature` is now a Structured Fields Byte Sequence (`sig=:...:`).
- `Signature-Input` is now a valid parameterized Inner List.
- `Signature-Agent` is a dictionary keyed to the covered signature label.
- The default directory identity is the HTTPS origin; the well-known path is resolved by the verifier.
- `keyid` is validated as the JWK Thumbprint required by the profile.
- `keyid` must match the configured private key, so key-pair configuration mistakes now fail immediately.
- Method, path, and query are covered to reduce replay scope.

If a 1.x application targets Cloudflare's currently deployed legacy verifier, migrate it with `cloudflare_legacy` first, verify the endpoint accepts the new RFC 9421 serialization, and move to `directory` once that endpoint supports the current draft.

## Development

```bash
composer update
composer qa
```

The CI matrix tests PHP 7.4 through 8.5 with current dependencies, tests a Composer-resolvable low dependency set separately, runs PHPStan 2 and PHP CS Fixer, audits production dependencies, and runs the live transport integration test weekly or on demand.

Commits use [Conventional Commits](https://www.conventionalcommits.org/). [Release Please](https://github.com/googleapis/release-please) turns them into a release pull request and applies Semantic Versioning: `fix` is patch, `feat` is minor, and `feat!` or a `BREAKING CHANGE` footer is major. See [RELEASE.md](RELEASE.md).

## Security

See [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

MIT. See [LICENSE.MIT](LICENSE.MIT).
