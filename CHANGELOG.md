# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project adheres to Semantic Versioning.

## [Unreleased]

### Changed
- Switched HTTP Message Signature `alg` parameter and JWK `alg` value to `ed25519`.
- Updated CI GitHub Actions to `actions/checkout@v6` and `actions/cache@v5`.
- Expanded CI PHP matrix to include PHP 8.5.

### Added
- Added tag-based `Release` workflow with optional Packagist refresh webhook.
- Added release runbook in `RELEASE.md`.
