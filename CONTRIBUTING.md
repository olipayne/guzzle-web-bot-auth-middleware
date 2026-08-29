# Contributing

Thanks for contributing.

## Development

1. Install dependencies:

```bash
composer update
```

2. Run checks locally:

```bash
composer validate --strict
composer lint
composer phpstan
composer test
```

The Composer lock file is intentionally ignored for this library so CI exercises the supported constraints instead of one application-style locked set.

3. Auto-fix coding style before committing when needed:

```bash
composer lint:fix
```

## Pull Requests

- Keep PRs focused and small.
- Add or update tests when behavior changes.
- Ensure CI passes before requesting review.
- Use a Conventional Commit PR title (`fix:`, `feat:`, `docs:`, and so on).
- Mark backwards-incompatible API or wire-format changes with `!` or a `BREAKING CHANGE` footer so Release Please selects the required major version.
- Treat changes to the active Web Bot Auth Internet-Draft as potential compatibility changes and cite the exact draft revision in the PR.
