# Illumio install helper maintenance

## Purpose

This repo maintains a one-time Illumio PCE single-node install helper and supporting client-install documentation. It should not contain client artifacts, secrets, package files, private keys, certificates, or environment-specific manifests.

## Run checks

```bash
scripts/check_repo.sh
```

CI runs the same checks on push and pull requests.

## Safe change workflow

1. Start from current `main`.
2. Keep installer changes small and reviewable.
3. Preserve safe defaults: no host mutation without `--yes`.
4. Keep `--dry-run` useful and non-mutating.
5. Do not commit RPMs, certs, private keys, password files, logs, or client manifests.
6. Update `CHANGELOG.md` for operator-visible changes.
7. Run `scripts/check_repo.sh`.
8. Push and confirm CI passes.

## Release convention

Tag reviewed client-install baselines with annotated tags:

```bash
git tag -a vYYYY.MM.DD-N -m "Illumio install helper release YYYY-MM-DD N"
git push origin main --tags
```

Example: `v2026.05.01-1`.

## Rollback or recovery

If a bad helper change is found before use, reset the repo to the last known-good tag or commit and rerun checks:

```bash
git fetch origin main --tags
git reset --hard <known-good-tag-or-commit>
scripts/check_repo.sh
```

If a bad helper was already run on a client host, treat that as a host recovery event. Follow the client's rollback/rebuild procedure and record the exact helper commit used.
