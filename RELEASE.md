# Release Process

Release Please is the single release path. It maintains `CHANGELOG.md`, chooses the next Semantic Version, creates the release pull request, and creates the tag and GitHub release after that pull request is merged.

## Normal workflow

1. Merge changes to `main` using Conventional Commit titles.
2. Review the automated `chore(main): release ...` pull request.
3. Confirm its proposed version and changelog. A `fix` commit produces a patch, `feat` produces a minor, and `feat!` or a `BREAKING CHANGE` footer produces a major.
4. Confirm CI passes, then merge the release pull request.
5. The Release Please workflow creates the `vX.Y.Z` tag and GitHub release.
6. Confirm Packagist sees the new tag. Its GitHub hook should update it automatically; the workflow also calls the Packagist update API when `PACKAGIST_USERNAME` and `PACKAGIST_TOKEN` are configured.

Do not create the tag or GitHub release by hand during the normal flow. That would bypass the release manifest and can cause Release Please to calculate from the wrong version.

## One-time repository settings

- GitHub Actions needs `contents: write`, `pull-requests: write`, and `issues: write`; these are declared in the workflow.
- Enable **Allow GitHub Actions to create and approve pull requests** in the repository's Actions settings if the default token cannot open the release pull request.
- Optional: configure `RELEASE_PLEASE_TOKEN` with repository contents, pull-request, and issue write access if release pull requests must trigger CI themselves. GitHub suppresses follow-on workflow runs for events created with the default `GITHUB_TOKEN`; without this secret, use the successful `main` CI run as the code gate and review the generated changelog/manifest-only release pull request.
- Connect the repository in Packagist.
- Optionally configure `PACKAGIST_USERNAME`, a Packagist safe API token as `PACKAGIST_TOKEN`, and `PACKAGIST_PACKAGE_URL`. Without the credentials, publishing relies on Packagist's GitHub hook.

## Version policy

Backwards-incompatible public API or wire-format changes require a breaking Conventional Commit and a major version. Do not use a patch release for a standards change merely because the PHP method signature stayed the same.

The current 1.x-to-2.x transition is major because the old fields were malformed or used a legacy draft format. Constructor argument order, the `sig` label, PHP 7.4 support, and Guzzle 7 support were deliberately retained where protocol correctness did not require a break.

Land this transition with a breaking Conventional Commit, for example `feat!: implement current Web Bot Auth signature format`, or include an equivalent `BREAKING CHANGE:` footer. That is what makes Release Please propose `v2.0.0` instead of an incorrect patch or minor release. The opt-in `cloudflare_legacy` discovery mode is a migration bridge for Cloudflare's older deployed `Signature-Agent` format; it does not change the standards-current default.

## Recovery

If automation fails, fix and rerun the workflow first. Before any manual recovery, compare `.release-please-manifest.json`, `CHANGELOG.md`, Git tags, GitHub Releases, and Packagist so they all resolve to the same version. A manual tag is a last resort and must be followed by updating the manifest in a reviewed pull request.
