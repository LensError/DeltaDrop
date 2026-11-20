#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Error: run this script as root on the Proxmox VE host." >&2
  exit 1
fi

for cmd in pct pveam pvesm pvesh openssl curl sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: required Proxmox/system command '$cmd' not found." >&2
    exit 1
  fi
done

GITHUB_REPO="${DELTADROP_GITHUB_REPO:-LensError/DeltaDrop}"

download_verified_release() {
  local repo="$1"
  local dest="$2"
  local arch="x86_64"
  if [[ "$(uname -m)" == "aarch64" ]]; then
    arch="aarch64"
  fi
  local asset="deltadrop-relay-linux-${arch}"
  local base_url="https://github.com/${repo}/releases/latest/download"
  echo "Downloading ${asset} and SHA256 checksum from ${repo}..."
  curl -fSL "${base_url}/${asset}" -o "$dest"
  curl -fSL "${base_url}/${asset}.sha256" -o "${dest}.sha256"
  local expected
  expected="$(awk '{print $1}' "${dest}.sha256")"
  local actual
  actual="$(sha256sum "$dest" | awk '{print $1}')"
  if [[ "$expected" != "$actual" ]]; then
    echo "Error: SHA256 mismatch! expected=${expected} actual=${actual}" >&2
    rm -f "$dest" "${dest}.sha256"
    exit 1
  fi
  rm -f "${dest}.sha256"
  chmod +x "$dest"
}

install_update_helper() {
  local ctid="$1"
  local tmp_helper
  tmp_helper="$(mktemp)"
  cat > "$tmp_helper" <<'HELPEREOF'
#!/usr/bin/env bash
set -euo pipefail
REPO="${DELTADROP_GITHUB_REPO:-LensError/DeltaDrop}"
ARCH="$(uname -m)"
ASSET="deltadrop-relay-linux-${ARCH}"
BASE_URL="https://github.com/${REPO}/releases/latest/download"
echo "Downloading ${ASSET} from ${REPO}..."
curl -fSL "${BASE_URL}/${ASSET}" -o /tmp/deltadrop-relay.new
curl -fSL "${BASE_URL}/${ASSET}.sha256" -o /tmp/deltadrop-relay.sha256
EXPECTED="$(awk '{print $1}' /tmp/deltadrop-relay.sha256)"
ACTUAL="$(sha256sum /tmp/deltadrop-relay.new | awk '{print $1}')"
if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  echo "Error: SHA256 mismatch!" >&2
  rm -f /tmp/deltadrop-relay.new /tmp/deltadrop-relay.sha256
  exit 1
fi
install -m 0755 /tmp/deltadrop-relay.new /usr/local/bin/deltadrop-relay
rm -f /tmp/deltadrop-relay.new /tmp/deltadrop-relay.sha256
systemctl restart deltadrop-relay
systemctl status deltadrop-relay --no-pager
HELPEREOF
  pct push "$ctid" "$tmp_helper" /usr/local/bin/deltadrop-update --perms 0755
  rm -f "$tmp_helper"
}

if [[ "${1:-}" == "--update" ]]; then
  UPDATE_CTID="${2:-}"
  if [[ -z "$UPDATE_CTID" ]]; then
    echo "Usage: $0 --update <CTID> [path-to-binary]" >&2
    exit 1
  fi
  BIN_PATH="${3:-}"
  TMP_BIN=""
  if [[ -z "$BIN_PATH" ]]; then
    if [[ -z "$GITHUB_REPO" ]]; then
      read -r -p "GitHub repo (owner/repo) for latest release: " GITHUB_REPO
    fi
    TMP_BIN="$(mktemp /tmp/deltadrop-relay-XXXXXX)"
    download_verified_release "$GITHUB_REPO" "$TMP_BIN"
    BIN_PATH="$TMP_BIN"
  fi
  echo "Upgrading deltadrop-relay inside LXC $UPDATE_CTID..."
  pct push "$UPDATE_CTID" "$BIN_PATH" /usr/local/bin/deltadrop-relay.new --perms 0755
  pct exec "$UPDATE_CTID" -- mv /usr/local/bin/deltadrop-relay.new /usr/local/bin/deltadrop-relay
  install_update_helper "$UPDATE_CTID"
  pct exec "$UPDATE_CTID" -- systemctl restart deltadrop-relay.service
  [[ -n "$TMP_BIN" ]] && rm -f "$TMP_BIN"
  echo "Upgrade complete. Status:"
  pct exec "$UPDATE_CTID" -- systemctl status deltadrop-relay --no-pager
  exit 0
fi

prompt_default() {
  local prompt="$1"
  local default="$2"
  local val
  read -r -p "$prompt [$default]: " val
  echo "${val:-$default}"
}

parse_size_to_bytes() {
  local raw="${1^^}"
  if [[ "$raw" =~ ^([0-9]+)G$ ]]; then
    echo $(( ${BASH_REMATCH[1]} * 1024 * 1024 * 1024 ))
  elif [[ "$raw" =~ ^([0-9]+)M$ ]]; then
    echo $(( ${BASH_REMATCH[1]} * 1024 * 1024 ))
  elif [[ "$raw" =~ ^[0-9]+$ ]]; then
    echo "$raw"
  else
    echo "Error: invalid size '$1' (use e.g. 5G, 512M, or bytes)" >&2
    exit 1
  fi
}

echo "=== DeltaDrop Relay - Proxmox LXC Setup ==="

NEXT_CTID="$(pvesh get /cluster/nextid 2>/dev/null || echo 100)"
CTID="$(prompt_default "Container ID (CTID)" "$NEXT_CTID")"
HOSTNAME="$(prompt_default "Container hostname" "deltadrop-relay")"
DEFAULT_LXC_PASS="$(openssl rand -base64 12 | tr -dc 'A-Za-z0-9' | head -c 14)"
LXC_PASSWORD="$(prompt_default "Container root password (for Proxmox Console login)" "$DEFAULT_LXC_PASS")"

echo ""
echo "Available Proxmox storage pools:"
pvesm status
echo ""
DEFAULT_POOL="$(pvesm status | awk 'NR>1 && $2 != "dir" {print $1; exit} NR>1 {print $1; exit}')"
DEFAULT_POOL="${DEFAULT_POOL:-local-lvm}"
STORAGE_POOL="$(prompt_default "Rootfs storage pool" "$DEFAULT_POOL")"
DISK_SIZE="$(prompt_default "Rootfs disk size (GB, e.g. 8)" "8")"
DISK_SIZE="${DISK_SIZE%G}"

RAM_MB="$(prompt_default "Memory (MB)" "512")"
SWAP_MB="$(prompt_default "Swap (MB)" "256")"
CORES="$(prompt_default "CPU cores" "1")"

DEFAULT_BRIDGE="$(ip -o link show type bridge | awk -F': ' '{print $2; exit}')"
DEFAULT_BRIDGE="${DEFAULT_BRIDGE:-vmbr0}"
BRIDGE="$(prompt_default "Network bridge" "$DEFAULT_BRIDGE")"
IP_MODE="$(prompt_default "IP mode (dhcp or static)" "dhcp")"
if [[ "${IP_MODE,,}" == "static" ]]; then
  STATIC_CIDR="$(prompt_default "Static IPv4 CIDR (e.g. 192.168.1.50/24)" "192.168.1.50/24")"
  GATEWAY="$(prompt_default "IPv4 Gateway (e.g. 192.168.1.1)" "192.168.1.1")"
  NET0="name=eth0,bridge=${BRIDGE},ip=${STATIC_CIDR},gw=${GATEWAY}"
else
  NET0="name=eth0,bridge=${BRIDGE},ip=dhcp"
fi

RELAY_PORT="$(prompt_default "Relay HTTP bind port" "8787")"
MAX_CACHE_GB="$(prompt_default "Max ephemeral cache quota in GB (MAX_CACHE_GB)" "50")"
CHUNK_TTL_HOURS="$(prompt_default "Chunk TTL in hours (CHUNK_TTL_HOURS)" "72")"

echo ""
ADMIN_USER="$(prompt_default "Initial admin username" "admin")"
read -r -s -p "Initial admin password: " ADMIN_PASS
echo ""
if [[ -z "$ADMIN_PASS" ]]; then
  echo "Error: admin password cannot be empty." >&2
  exit 1
fi

GENERATED_GATE="$(openssl rand -hex 24)"
echo ""
RELAY_NETWORK_SECRET="$(prompt_default "Optional RELAY_NETWORK_SECRET (X-DeltaDrop-Gate, blank to disable)" "$GENERATED_GATE")"

echo ""
echo "Select ingress mode:"
echo "  1) Tailscale only (bind 0.0.0.0:${RELAY_PORT} over Tailscale/LAN)"
echo "  2) Caddy2 HTTPS (automatic TLS for a public domain)"
echo "  3) Cloudflare Tunnel (cloudflared token, binds 127.0.0.1:${RELAY_PORT})"
INGRESS_MODE="$(prompt_default "Choose ingress mode (1, 2, or 3)" "1")"

TLS_DOMAIN=""
CF_TUNNEL_TOKEN=""
CF_PUBLIC_HOST=""
if [[ "$INGRESS_MODE" == "2" ]]; then
  TLS_DOMAIN="$(prompt_default "HTTPS domain for Caddy2 (e.g. sync.example.com)" "")"
  if [[ -z "$TLS_DOMAIN" ]]; then
    echo "Error: domain is required for Caddy2 HTTPS mode." >&2
    exit 1
  fi
elif [[ "$INGRESS_MODE" == "3" ]]; then
  read -r -s -p "Cloudflare Tunnel token (cloudflared service install): " CF_TUNNEL_TOKEN
  echo ""
  if [[ -z "$CF_TUNNEL_TOKEN" ]]; then
    echo "Error: Cloudflare Tunnel token is required." >&2
    exit 1
  fi
  CF_PUBLIC_HOST="$(prompt_default "Public hostname mapped to this tunnel (e.g. sync.example.com)" "")"
fi

echo ""
echo "Deployment method:"
echo "  1) Prebuilt static Linux binary (local file or GitHub Release with SHA256 check)"
echo "  2) Build from source inside the LXC (temporarily bumps RAM to 2048MB during cargo build)"
DEPLOY_MODE="$(prompt_default "Choose deployment method (1 or 2)" "1")"

PREBUILT_BIN=""
DOWNLOADED_TMP=""
SRC_DIR=""
if [[ "$DEPLOY_MODE" == "1" ]]; then
  PREBUILT_BIN="$(prompt_default "Local binary path (leave blank to download latest GitHub Release)" "")"
  if [[ -z "$PREBUILT_BIN" ]]; then
    if [[ -z "$GITHUB_REPO" ]]; then
      GITHUB_REPO="$(prompt_default "GitHub repository (owner/repo)" "LensError/DeltaDrop")"
    fi
    if [[ -z "$GITHUB_REPO" ]]; then
      echo "Error: either a local binary path or GitHub repo is required." >&2
      exit 1
    fi
    DOWNLOADED_TMP="$(mktemp /tmp/deltadrop-relay-XXXXXX)"
    download_verified_release "$GITHUB_REPO" "$DOWNLOADED_TMP"
    PREBUILT_BIN="$DOWNLOADED_TMP"
  elif [[ ! -f "$PREBUILT_BIN" ]]; then
    echo "Error: binary not found at $PREBUILT_BIN" >&2
    exit 1
  fi
else
  SRC_DIR="$(prompt_default "Path to deltadrop workspace on Proxmox host" "./deltadrop")"
  if [[ ! -f "$SRC_DIR/Cargo.toml" ]]; then
    echo "Error: Cargo.toml not found in $SRC_DIR" >&2
    exit 1
  fi
fi

# Locate or download minimal Debian 12 template
TEMPLATE_STORAGE="local"
TEMPLATE_NAME="$(pveam list "$TEMPLATE_STORAGE" | awk '/debian-12-standard/ {print $1; exit}')"
if [[ -z "$TEMPLATE_NAME" ]]; then
  echo "Updating template index and downloading Debian 12 standard template..."
  pveam update
  AVAIL_TPL="$(pveam available --section system | awk '/debian-12-standard/ {print $2; exit}')"
  if [[ -z "$AVAIL_TPL" ]]; then
    echo "Error: could not find debian-12-standard template in pveam." >&2
    exit 1
  fi
  pveam download "$TEMPLATE_STORAGE" "$AVAIL_TPL"
  TEMPLATE_NAME="${TEMPLATE_STORAGE}:vztmpl/${AVAIL_TPL}"
fi

echo "Creating unprivileged LXC $CTID ($HOSTNAME)..."
pct create "$CTID" "$TEMPLATE_NAME" \
  --hostname "$HOSTNAME" \
  --password "$LXC_PASSWORD" \
  --storage "$STORAGE_POOL" \
  --rootfs "${STORAGE_POOL}:${DISK_SIZE}" \
  --memory "$RAM_MB" \
  --swap "$SWAP_MB" \
  --cores "$CORES" \
  --net0 "$NET0" \
  --unprivileged 1 \
  --features nesting=1 \
  --onboot 1

pct start "$CTID"
echo "Waiting for container network..."
for _ in $(seq 1 30); do
  if pct exec "$CTID" -- hostname -I 2>/dev/null | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    break
  fi
  sleep 1
done

pct exec "$CTID" -- bash -c "apt-get update && apt-get install -y ca-certificates curl"
pct exec "$CTID" -- useradd --system --home /var/lib/deltadrop --create-home --shell /usr/sbin/nologin deltadrop || true
pct exec "$CTID" -- mkdir -p /etc/deltadrop /var/lib/deltadrop/blobs
pct exec "$CTID" -- chown -R deltadrop:deltadrop /var/lib/deltadrop

if [[ "$DEPLOY_MODE" == "1" ]]; then
  pct push "$CTID" "$PREBUILT_BIN" /usr/local/bin/deltadrop-relay --perms 0755
else
  if (( RAM_MB < 2048 )); then
    pct set "$CTID" --memory 2048 --swap 1024
  fi
  pct exec "$CTID" -- apt-get install -y build-essential pkg-config libssl-dev
  pct exec "$CTID" -- bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
  TAR_TMP="$(mktemp /tmp/deltadrop-src-XXXXXX.tar.gz)"
  tar --exclude='./target' --exclude='./.git' -czf "$TAR_TMP" -C "$SRC_DIR" .
  pct push "$CTID" "$TAR_TMP" /tmp/deltadrop-src.tar.gz
  rm -f "$TAR_TMP"
  pct exec "$CTID" -- bash -c "
    set -e
    mkdir -p /tmp/deltadrop-build
    tar -xzf /tmp/deltadrop-src.tar.gz -C /tmp/deltadrop-build
    cd /tmp/deltadrop-build
    sed -i '/deltadrop-client/d;/lumenic/d' Cargo.toml
    /root/.cargo/bin/cargo build --release -p deltadrop-relay
    install -m 0755 target/release/deltadrop-relay /usr/local/bin/deltadrop-relay
    rm -rf /tmp/deltadrop-build /tmp/deltadrop-src.tar.gz /root/.cargo /root/.rustup
    apt-get purge -y build-essential && apt-get autoremove -y
  "
  pct set "$CTID" --memory "$RAM_MB" --swap "$SWAP_MB"
fi

BIND_HOST="0.0.0.0"
if [[ "$INGRESS_MODE" == "2" || "$INGRESS_MODE" == "3" ]]; then
  BIND_HOST="127.0.0.1"
fi

ENV_TMP="$(mktemp)"
UNIT_TMP="$(mktemp)"
CADDY_TMP="$(mktemp)"
trap 'rm -f "$ENV_TMP" "$UNIT_TMP" "$CADDY_TMP"' EXIT

cat > "$ENV_TMP" <<EOF
DELTADROP_BIND=${BIND_HOST}:${RELAY_PORT}
DELTADROP_DATA_DIR=/var/lib/deltadrop
MAX_CACHE_GB=${MAX_CACHE_GB}
CHUNK_TTL_HOURS=${CHUNK_TTL_HOURS}
RELAY_NETWORK_SECRET=${RELAY_NETWORK_SECRET}
RUST_LOG=deltadrop_relay=info
EOF
pct push "$CTID" "$ENV_TMP" /etc/deltadrop/relay.env --perms 0600

pct exec "$CTID" -- su -s /bin/sh deltadrop -c "DELTADROP_DATA_DIR=/var/lib/deltadrop /usr/local/bin/deltadrop-relay user create --username '${ADMIN_USER}' --password '${ADMIN_PASS}' --admin"

cat > "$UNIT_TMP" <<EOF
[Unit]
Description=DeltaDrop Ephemeral Relay Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=deltadrop
Group=deltadrop
EnvironmentFile=/etc/deltadrop/relay.env
ExecStart=/usr/local/bin/deltadrop-relay
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
MemoryMax=${RAM_MB}M
ReadWritePaths=/var/lib/deltadrop

[Install]
WantedBy=multi-user.target
EOF
pct push "$CTID" "$UNIT_TMP" /etc/systemd/system/deltadrop-relay.service --perms 0644
install_update_helper "$CTID"
pct exec "$CTID" -- systemctl daemon-reload
pct exec "$CTID" -- systemctl enable --now deltadrop-relay.service

if [[ "$INGRESS_MODE" == "2" ]]; then
  echo "Installing Caddy for automatic HTTPS on ${TLS_DOMAIN}..."
  pct exec "$CTID" -- bash -c "
    set -e
    apt-get install -y debian-keyring debian-archive-keyring apt-transport-https gnupg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update && apt-get install -y caddy
  "
  cat > "$CADDY_TMP" <<EOF
${TLS_DOMAIN} {
    reverse_proxy 127.0.0.1:${RELAY_PORT}
}
EOF
  pct push "$CTID" "$CADDY_TMP" /etc/caddy/Caddyfile --perms 0644
  pct exec "$CTID" -- systemctl enable --now caddy
  RELAY_URL="https://${TLS_DOMAIN}"
elif [[ "$INGRESS_MODE" == "3" ]]; then
  echo "Installing cloudflared for Cloudflare Tunnel..."
  pct exec "$CTID" -- bash -c "
    set -e
    curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o /tmp/cloudflared.deb
    dpkg -i /tmp/cloudflared.deb
    rm -f /tmp/cloudflared.deb
    cloudflared service install '${CF_TUNNEL_TOKEN}'
  "
  RELAY_URL="https://${CF_PUBLIC_HOST:-<your-tunnel-domain>}"
else
  LXC_IP="$(pct exec "$CTID" -- hostname -I | awk '{print $1}')"
  LXC_IP="${LXC_IP:-<LXC_IP>}"
  RELAY_URL="http://${LXC_IP}:${RELAY_PORT}"
fi

[[ -n "${DOWNLOADED_TMP:-}" ]] && rm -f "$DOWNLOADED_TMP"

echo ""
echo "=== DeltaDrop Relay Deployed! ==="
echo "LXC Console login: root / ${LXC_PASSWORD}"
echo "Update later from inside LXC: deltadrop-update"
echo "Service status: pct exec $CTID -- systemctl status deltadrop-relay --no-pager"
echo ""
echo "Sign in on DeltaDrop Client with:"
echo "  Relay Address : ${RELAY_URL}"
echo "  Username      : ${ADMIN_USER} (or ${ADMIN_USER}@${RELAY_URL#https://})"
if [[ -n "$RELAY_NETWORK_SECRET" ]]; then
  echo "  Network Gate  : ${RELAY_NETWORK_SECRET} (X-DeltaDrop-Gate)"
fi
