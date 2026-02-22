# Release Process

This package is published through Git tags and Packagist.

## One-Time Setup

1. Ensure the repository is connected in Packagist.
2. Add these repository secrets for automatic Packagist refresh on release:
   - `PACKAGIST_PACKAGE_URL` (for example, `https://github.com/olipayne/guzzle-web-bot-auth-middleware`)
   - `PACKAGIST_TOKEN` (Packagist API token)

## Release Checklist

1. Update `CHANGELOG.md`.
2. Ensure CI is green on `main`.
3. Create and push a semantic version tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

4. Confirm the `Release` workflow completed successfully.
5. Confirm the new version appears on Packagist.

If Packagist does not update automatically, run a manual update in Packagist for this package.
