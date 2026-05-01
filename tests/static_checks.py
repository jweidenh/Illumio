#!/usr/bin/env python3
"""Static checks for the Illumio install helper."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install_illumio.sh"
text = SCRIPT.read_text(encoding="utf-8")

checks = {
    "script uses strict bash mode": "set -euo pipefail" in text,
    "real execution requires explicit --yes": "Refusing to mutate this host without --yes" in text,
    "dry-run mode is implemented": "--dry-run" in text and "DRY_RUN" in text,
    "site fqdn has no unsafe default": 'PCE_FQDN="${PCE_FQDN:-}"' in text,
    "load balancer ip has no unsafe default": 'LOAD_BALANCER_IP="${LOAD_BALANCER_IP:-}"' in text,
    "notification email has no unsafe default": 'EMAIL_ADDR="${EMAIL_ADDR:-}"' in text,
    "runtime yaml references installed certificate paths": "/var/lib/illumio-pce/cert/server.key" in text,
    "password file supported instead of hardcoded password": "ADMIN_PASSWORD_FILE" in text,
    "placeholder guard exists": "validate_not_placeholder" in text,
    "expect reads password from file path instead of process environment": "<<'EOF'" in text and "$env(ADMIN_PASSWORD_PATH)" in text and "$env(ADMIN_PASSWORD)" not in text,
    "inherited password exports are cleared before reads": "unset ADMIN_PASSWORD ADMIN_PASSWORD2" in text,
}

failures = [name for name, ok in checks.items() if not ok]

for forbidden in [
    'ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"',
    'LOAD_BALANCER_IP="x.x.x.x"',
    'PCE_FQDN="illumio.dev"',
    'EMAIL_ADDR="admin@email.com"',
]:
    if forbidden in text:
        failures.append(f"forbidden legacy placeholder/default remains: {forbidden}")

for assignment in re.findall(r"(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|PRIVATE_KEY)[A-Z0-9_]*)=(.+)$", text):
    name, value = assignment
    value = value.strip()
    if name.endswith(("_FILE", "_PATH")):
        continue
    if "$" in value or "${" in value or "$(" in value or value in {'""', "''"}:
        continue
    failures.append(f"potential hardcoded sensitive assignment found: {name}")

if failures:
    print("Static checks failed:", file=sys.stderr)
    for failure in failures:
        print(f"- {failure}", file=sys.stderr)
    sys.exit(1)

print(f"{len(checks)} static checks passed")
