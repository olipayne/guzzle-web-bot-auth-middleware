# Contributing

Thanks for contributing.

## Development

1. Install dependencies:

```bash
composer install
```

2. Run checks locally:

```bash
composer validate --strict
composer lint
composer phpstan
composer test
```

3. Auto-fix coding style before committing when needed:

```bash
composer lint:fix
```

## Pull Requests

- Keep PRs focused and small.
- Add or update tests when behavior changes.
- Ensure CI passes before requesting review.
