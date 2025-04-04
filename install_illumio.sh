#!/usr/bin/env bash

###############################################################################
# Illumio PCE Single-Node Installation Script                                 #
###############################################################################

set -euo pipefail

### 0. Variables and Prerequisites ###

# File paths
ILLUMIO_RPM_KEY="/usr/local/src/illumio-pce-ui-24.5.0.UI1-2981.x86_64.signingkey"
ILLUMIO_PCE_RPM="/usr/local/src/illumio-pce-24.5.0-2379.el9.x86_64.rpm"
ILLUMIO_UI_RPM="/usr/local/src/illumio-pce-ui-24.5.0.UI1-2981.x86_64.rpm"
SERVER_CERT_PATH="/usr/local/src/illumio.dev.crt"
SERVER_KEY_PATH="/usr/local/src/illumio.dev.key"
CA_CERT="/usr/local/src/ca.crt"
RUN_ENV_FILE="/etc/illumio-pce/runtime_env.yml"

# Configuration variables
PCE_FQDN="illumio.dev"
LOGIN_BANNER="No unauthorized access!"
EMAIL_ADDR="admin@email.com"
SERVICE_DISCOVERY_FQDN="$PCE_FQDN"
LOAD_BALANCER_IP="x.x.x.x"

# Randomly generate the service discovery encryption key
SERVICE_DISCOVERY_KEY="$(openssl rand -base64 32)"

# Admin details (override via environment vars if desired)
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
FULL_NAME="${FULL_NAME:-}"
ORG_NAME="${ORG_NAME:-}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"

# Function to handle errors gracefully
trap 'echo "[ERROR] An unexpected error occurred. Exiting." >&2' ERR

if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] This script must be run as root." >&2
  exit 1
fi

# Validate required files exist
required_files=("$ILLUMIO_RPM_KEY" "$ILLUMIO_PCE_RPM" "$SERVER_CERT_PATH" "$SERVER_KEY_PATH" "$CA_CERT")
for file in "${required_files[@]}"; do
  if [[ ! -f "${file}" ]]; then
    echo "[ERROR] Required file ${file} not found." >&2
    exit 1
  fi
done

# Update CA Trust
echo "[INFO] Updating CA trust store..."
cp "$CA_CERT" /etc/pki/ca-trust/source/anchors/
update-ca-trust

### 1. Basic OS Preparation ###
echo "[INFO] Installing prerequisite packages..."
dnf install -y \
  bind-utils bzip2 ca-certificates chkconfig initscripts ipset logrotate \
  net-tools openssh-clients patch postfix procps-ng tcpdump traceroute \
  util-linux

echo "[INFO] Installing expect if not present..."
dnf install -y expect

# Configure file limits and sysctl
mkdir -p /etc/systemd/system/illumio-pce.service.d
cat <<EOF > /etc/systemd/system/illumio-pce.service.d/override.conf
[Service]
LimitCORE=0
LimitNOFILE=65535
LimitNPROC=65535
EOF

echo "[INFO] Configuring system limits and parameters..."
mkdir -p /etc/sysctl.d
cat <<EOF > /etc/sysctl.d/99-illumio.conf
fs.file-max = 2000000
net.core.somaxconn = 16384
EOF

sysctl --system

modprobe nf_conntrack
echo 262144 > /sys/module/nf_conntrack/parameters/hashsize
echo "options nf_conntrack hashsize=262144" > /etc/modprobe.d/illumio.conf

systemctl daemon-reload
sleep 30

### 2. Install Illumio PCE Software ###
echo "[INFO] Importing Illumio GPG key..."
rpm --import "$ILLUMIO_RPM_KEY"

echo "[INFO] Installing Illumio PCE RPM..."
rpm -Uvh "$ILLUMIO_PCE_RPM"

if [[ -f "$ILLUMIO_UI_RPM" ]]; then
    echo "[INFO] Installing Illumio PCE UI..."
    rpm -Uvh "$ILLUMIO_UI_RPM"
fi

### 3. Prepare Certificates for PCE ###
echo "[INFO] Setting up certificates..."
mkdir -p /var/lib/illumio-pce/cert
cp "$SERVER_CERT_PATH" /var/lib/illumio-pce/cert/server.crt
cp "$SERVER_KEY_PATH" /var/lib/illumio-pce/cert/server.key
chmod 400 /var/lib/illumio-pce/cert/server.*
chown ilo-pce:ilo-pce /var/lib/illumio-pce/cert/server.*
chown root:ilo-pce /etc/illumio-pce

### 4. Generate the runtime_env.yml ###
echo "[INFO] Generating runtime environment file..."
mkdir -p "$(dirname "$RUN_ENV_FILE")"
cat <<EOF > "$RUN_ENV_FILE"
install_root: "/opt/illumio-pce"
runtime_data_root: "/var/lib/illumio-pce/runtime"
persistent_data_root: "/var/lib/illumio-pce/data"
ephemeral_data_root: "/var/lib/illumio-pce/tmp"
log_dir: "/var/log/illumio-pce"
private_key_cache_dir: "/var/lib/illumio-pce/keys"
pce_fqdn: $PCE_FQDN
login_banner: "$LOGIN_BANNER"
service_discovery_fqdn: $SERVICE_DISCOVERY_FQDN
cluster_public_ips:
  cluster_fqdn:
  - $LOAD_BALANCER_IP
node_type: snc0
web_service_private_key: "$SERVER_KEY_PATH"
web_service_certificate: "$SERVER_CERT_PATH"
email_address: $EMAIL_ADDR
service_discovery_encryption_key: $SERVICE_DISCOVERY_KEY
insecure_tls_weak_ciphers_enabled: false
expose_user_invitation_link: true
EOF

chgrp ilo-pce "$RUN_ENV_FILE"

### 5. Validate runtime_env.yml ###
echo "[INFO] Validating runtime environment..."
if ! illumio-pce-env setup --list --test; then
  echo "[ERROR] Illumio PCE environment validation failed." >&2
  exit 1
fi

### 6. Start PCE and Initialize DB ###
echo "[INFO] Starting PCE at runlevel 1..."
sudo -u ilo-pce illumio-pce-ctl start --runlevel 1
# Give the process time to start
sleep 120

echo "[INFO] Initializing PCE database..."
sudo -u ilo-pce illumio-pce-db-management setup

echo "[INFO] Setting PCE runlevel to 5..."
sudo -u ilo-pce illumio-pce-ctl set-runlevel 5
sleep 120

echo "[INFO] Checking cluster status..."
sudo -u ilo-pce illumio-pce-ctl cluster-status

### 7. Create Initial PCE User (Non-interactive via expect) ###

echo "[INFO] Checking administrative details..."
if [[ -z "$ADMIN_EMAIL" ]]; then
  read -p "Enter initial admin email address: " ADMIN_EMAIL
fi
if [[ -z "$FULL_NAME" ]]; then
  read -p "Enter full name: " FULL_NAME
fi
if [[ -z "$ORG_NAME" ]]; then
  read -p "Enter Organization Name: " ORG_NAME
fi
if [[ -z "$ADMIN_PASSWORD" ]]; then
  read -s -p "Enter admin password: " ADMIN_PASSWORD
  echo
  read -s -p "Re-enter admin password: " ADMIN_PASSWORD2
  echo
  if [[ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD2" ]]; then
    echo "[ERROR] Passwords do not match. Exiting." >&2
    exit 1
  fi
fi

echo "[INFO] Creating initial PCE user account..."
/usr/bin/expect <<EOF
spawn sudo -u ilo-pce illumio-pce-db-management create-domain \
  --user-name "$ADMIN_EMAIL" \
  --full-name "$FULL_NAME" \
  --org-name "$ORG_NAME"
expect "Enter Password:"
send "$ADMIN_PASSWORD\r"
expect "Re-enter Password:"
send "$ADMIN_PASSWORD\r"
expect eof
EOF

echo "[INFO] Installation complete. You should now be able to access the PCE via https://$PCE_FQDN:8443"
