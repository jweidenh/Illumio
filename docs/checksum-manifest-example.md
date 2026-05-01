# Checksum manifest example

`CHECKSUM_MANIFEST` points to a standard `sha256sum --check --strict` manifest. Generate it from trusted artifacts on the staging host. Do not invent hashes and do not commit client manifests.

Example placeholder format only:

```text
<64 lowercase hex sha256>  illumio-pce-ui-<version>.x86_64.signingkey
<64 lowercase hex sha256>  illumio-pce-<version>.el9.x86_64.rpm
<64 lowercase hex sha256>  illumio-pce-ui-<version>.x86_64.rpm
<64 lowercase hex sha256>  server.crt
<64 lowercase hex sha256>  server.key
<64 lowercase hex sha256>  ca.crt
```

Create a real manifest from trusted staged files:

```bash
cd /usr/local/src
sha256sum \
  illumio-pce-ui-<version>.x86_64.signingkey \
  illumio-pce-<version>.el9.x86_64.rpm \
  illumio-pce-ui-<version>.x86_64.rpm \
  server.crt \
  server.key \
  ca.crt \
  > illumio-checksums.sha256
chmod 600 illumio-checksums.sha256
```

Use it during dry run and install:

```bash
sudo CHECKSUM_MANIFEST=/usr/local/src/illumio-checksums.sha256 \
  PCE_FQDN=pce.example.internal \
  LOAD_BALANCER_IP=192.0.2.10 \
  EMAIL_ADDR=admin@example.internal \
  ./install_illumio.sh --dry-run
```

Paths in the manifest may be absolute, or relative to the manifest file's directory.
