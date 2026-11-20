# DeltaDrop

Fast, end-to-end encrypted file sync across Windows, Linux, and macOS using a lightweight self-hosted relay.

## Features

- **Zero-knowledge account login:** Sign in with Relay Address + Username + Password (or `user@relay` shorthand). Argon2id derives `auth_key` and `vault_key` locally; `vault_key` never leaves your device.
- **Multi-user admin & isolated workspaces:** Admins can create, reset, disable, or delete sub-users; each user has an isolated encrypted chunk workspace.
- **Demand-driven ephemeral relay cache:** Publishing a folder uploads only lightweight encrypted manifests. Chunks stream on demand over WebSocket + HTTP (<= 16 MiB) and are evicted immediately on `ACK`, or by `CHUNK_TTL_HOURS` / `MAX_CACHE_GB` LRU.
- **Real E2E encryption:** File contents, filenames, folder names, and device names are encrypted client-side with ChaCha20-Poly1305 before leaving your device.
- **Large-file streaming & delta sync:** Files over 256 KiB are split into content-addressed FastCDC chunks and deduplicated.
- **Two-way sync & conflict protection:** All folders use two-way sync with `.sync-conflict-*` backups, stale-host reconciliation, and non-destructive re-linking after OS reinstalls.
- **Auto-detected ignore presets:** Built-in toggles for Unity, Rust, Node/Web, Python, C/C++/IDE, and Git/OS Junk plus `.deltadropignore` sync and live path testing.
- **SHA-256 verified updates:** Both `deltadrop-client` (in-app updater) and `deltadrop-relay` (`deltadrop-update`) verify release `SHA256SUMS` before replacing binaries.

---

## Quick Start (End Users)

### 1. Deploy the Relay (choose one)

#### Option A: Proxmox LXC (one command on your Proxmox node Shell)

Open your Proxmox node **Shell** (not a container Console) as `root` and run:

```bash
curl -fsSL https://raw.githubusercontent.com/LensError/DeltaDrop/main/deploy/setup-proxmox-lxc.sh -o /tmp/setup-proxmox-lxc.sh && bash /tmp/setup-proxmox-lxc.sh
```

The script creates a Debian 12 LXC, downloads and verifies the static `deltadrop-relay` binary, configures your initial admin account, cache limits (`MAX_CACHE_GB`, `CHUNK_TTL_HOURS`), optional `RELAY_NETWORK_SECRET` (`X-DeltaDrop-Gate`), and ingress (**Tailscale only**, **Caddy2 HTTPS**, or **Cloudflare Tunnel**).

To create additional users from inside the LXC:
```bash
DELTADROP_DATA_DIR=/var/lib/deltadrop deltadrop-relay user create --username alice --password '...'
```

To update an existing LXC later:
- From the Proxmox node Shell: `bash /tmp/setup-proxmox-lxc.sh --update <CTID>`
- Or from inside the LXC: `deltadrop-update`

#### Option B: Docker / Docker Compose

```bash
git clone https://github.com/LensError/DeltaDrop.git
cd DeltaDrop/deploy
docker compose up -d
docker compose exec deltadrop-relay deltadrop-relay user create --username admin --password 'your-password' --admin
```

To enable automatic HTTPS with Caddy:

```bash
TLS_DOMAIN="relay.example.com" docker compose --profile tls up -d
```

---

### 2. Install & Sign In on the Desktop Client

1. Download the latest release for your OS from [GitHub Releases](https://github.com/LensError/DeltaDrop/releases/latest):
   - **Windows:** `deltadrop-client-windows-x86_64.zip`
   - **Linux:** `deltadrop-client-linux-x86_64.tar.gz`
   - **macOS:** `deltadrop-client-macos-universal.tar.gz`
2. Launch `deltadrop-client`.
3. Sign in with your **Relay Address**, **Username** (or paste `username@relay-host` to auto-fill both), **Password**, and **Device Name**.
4. Choose **Share a Local Folder** or **Sync from Another PC** to start two-way syncing.

---

## CLI Flags

- `--config <path>`: Use a custom `deltadrop-config.json` path (default: OS app data directory).
- `--minimized`: Start minimized to the system tray (shows window on first-run setup).
- `--headless`: Run sync daemon without a GUI window (for servers/systemd).

---

## `.deltadropignore`

Ignore rules are stored in `.deltadropignore` at the root of each sync folder and synced across peers. Internal safety patterns (`*.sync-conflict-*`, `.deltadrop-tmp*`) are always ignored. Example:

```gitignore
*.tmp
*.bak
*.iso
scratch/
```

---

## Building from Source

Requires Rust (`stable`).

```bash
git clone https://github.com/LensError/DeltaDrop.git
cd DeltaDrop
cargo build --release
```

Binaries are output to `target/release/deltadrop-relay` and `target/release/deltadrop-client` (`.exe` on Windows).
