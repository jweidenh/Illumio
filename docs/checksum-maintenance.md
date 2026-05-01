# Checksum manifest maintenance

Checksum manifests are client/install artifacts. They should be generated from trusted staged files and stored with the engagement's protected install materials, not in this repository.

## Where to store manifests

Recommended locations:

- Client-approved secure file share
- Ticket attachment with restricted access
- Password-manager secure document
- Target host staging directory such as `/usr/local/src`, with mode `0600`

Do not commit real manifests if they reveal client package names, paths, versions, or certificate filenames that should stay private.

## When package versions change

1. Obtain new packages from the trusted source.
2. Stage them outside the repo.
3. Generate a new manifest from those exact files.
4. Validate the manifest with `scripts/validate_manifest.sh`.
5. Run `install_illumio.sh --dry-run` with `CHECKSUM_MANIFEST` set.
6. Record the manifest location and package versions in the client install record.
7. Retire the old manifest according to the client retention policy.

## Validate a manifest

```bash
scripts/validate_manifest.sh /usr/local/src/illumio-checksums.sha256
```

The script runs `sha256sum --check --strict` from the manifest directory, matching installer behavior.

## Avoid client-specific data in Git

Keep these out of Git:

- real manifests
- RPMs
- certificates and private keys
- password files
- client hostnames, IP addresses, organization names, and package paths when they are not meant to be public
