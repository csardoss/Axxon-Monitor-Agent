# AxxonOne Monitoring Agent

Lightweight monitoring agent for AxxonOne VMS servers. Collects telemetry (CPU, GPU, storage, AI efficiency metrics), alarm events, and provides API proxy capabilities — all reported back to a central gateway over gRPC with mTLS encryption.

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh | sudo bash
```

The interactive installer will prompt you for:
1. **Gateway address** — the central monitoring server (default: `axxonmonitor.digitalsecurityguard.com:18443`)
2. **Enrollment token** — one-time token from the gateway admin (used for automatic certificate provisioning)
3. **Download method** — device pairing via Artifact Portal, API token, or skip if binary is already installed

## Prerequisites

- Linux (amd64)
- `curl`, `sha256sum`, `systemctl`, `jq`, `openssl`
- Network access to the gateway on port 18443 (outbound only)

## Installation

### Step 1: Get an Enrollment Token

Ask your administrator to generate a token from the Agent Manager UI. Tokens are single-use and valid for 24 hours. The enrollment token serves two purposes:
- **Identity** — registers the agent with the gateway
- **Certificate provisioning** — the installer uses the token to automatically generate a private key, submit a CSR, and receive signed TLS certificates

### Step 2: Run the Installer

```bash
curl -fsSL https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh | sudo bash
```

Or download and run manually:

```bash
wget https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh
chmod +x install.sh
sudo ./install.sh
```

The installer will:
1. Prompt for gateway address and enrollment token
2. Download the agent binary from the **Artifact Portal** (device pairing or API token)
3. Verify the SHA256 checksum
4. Generate a private key locally and provision TLS certificates via CSR
5. Create configuration at `/etc/axxon-agent/config.yaml`
6. Install and start a hardened systemd service

### Step 3: Verify

```bash
# Check service status
sudo systemctl status axxon-agent

# Watch logs
sudo journalctl -u axxon-agent -f
```

The agent should connect to the gateway and appear in the Agent Manager UI within 30 seconds.

## Binary Download Methods

The installer offers three ways to download the agent binary:

### 1. Device Pairing (default)
The installer starts a pairing flow with the Artifact Portal. You'll see a URL and pairing code — open the URL in a browser, approve the device, and the binary downloads automatically.

### 2. API Token
If you have a pre-created API token (`apt_...`), paste it when prompted. The binary downloads directly without browser interaction.

### 3. Skip / Manual
If the binary is already installed at `/usr/local/bin/axxon-agent` (e.g., copied via SCP), choose skip. The installer proceeds with configuration only.

## Updates

### Automatic Updates (Managed Rollouts)

Agents update automatically when a new version is published. The process is fully managed from the gateway — no SSH access to agent machines is needed.

**How it works:**

1. The gateway periodically checks the Artifact Portal for new agent versions
2. New binaries are downloaded and cached on the gateway with SHA256 verification
3. An administrator creates a **rollout** from the Agent Manager UI, setting a rollout percentage (e.g., 10% → 50% → 100%)
4. The gateway pushes an `UpdateAvailable` message to eligible agents over the existing gRPC connection
5. Each agent downloads the binary from the gateway, verifies the SHA256 checksum, and stages it
6. The agent restarts via systemd and performs a post-update health check (gateway connection + heartbeats)
7. If the health check fails or the agent crash-loops, it **automatically rolls back** to the previous version

**Safety features:**

- **Staged rollouts** — roll out to a percentage of agents before going fleet-wide
- **Automatic pause** — if the failure rate exceeds 10%, the rollout pauses automatically
- **Automatic rollback** — failed health checks or 3+ rapid restarts trigger rollback to the previous version
- **Failed version tracking** — versions that failed on an agent are not retried without manual intervention
- **Admin controls** — pause, resume, or force-rollback from the Agent Manager UI

No action is required on agent machines for automatic updates.

### Manual Upgrade

If you need to upgrade an agent manually (e.g., the agent is offline or automatic updates are not yet enabled):

```bash
# Stop the agent
sudo systemctl stop axxon-agent

# Replace the binary (download from Artifact Portal or copy via SCP)
sudo cp /path/to/new/axxon-agent /usr/local/bin/axxon-agent
sudo chmod +x /usr/local/bin/axxon-agent

# Restart
sudo systemctl start axxon-agent

# Verify
sudo journalctl -u axxon-agent -n 20 --no-pager
```

Or remove the existing binary and re-run the installer to download the latest version:

```bash
sudo systemctl stop axxon-agent
sudo rm /usr/local/bin/axxon-agent
curl -fsSL https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh | sudo bash
```

Configuration, certificates, and data are preserved across upgrades.

## File Locations

| Path | Description |
|------|-------------|
| `/usr/local/bin/axxon-agent` | Agent binary |
| `/etc/axxon-agent/config.yaml` | Configuration file |
| `/etc/axxon-agent/agent.crt` | Agent TLS certificate (auto-provisioned) |
| `/etc/axxon-agent/agent.key` | Agent private key (never leaves the machine) |
| `/etc/axxon-agent/ca.crt` | CA certificate chain |
| `/etc/axxon-agent/agent-id` | Assigned agent ID (auto-generated on enrollment) |
| `/var/lib/axxon-agent/alarms.db` | Local alarm buffer (SQLite) |

## Configuration

Edit `/etc/axxon-agent/config.yaml`:

```yaml
# Gateway connection
gateway_addr: "axxonmonitor.digitalsecurityguard.com:18443"

# Identity (one of these)
enrollment_token: "enroll_..."    # First-time enrollment
# agent_id: "uuid-here"          # Set automatically after enrollment

# TLS certificates (auto-provisioned by installer)
cert_file: "/etc/axxon-agent/agent.crt"
key_file: "/etc/axxon-agent/agent.key"
ca_file: "/etc/axxon-agent/ca.crt"

# AxxonOne server (local connection)
axxon_port: 80                    # AxxonOne HTTP API port

# Alarm buffer
alarm_db_path: "/var/lib/axxon-agent/alarms.db"

# Timing
heartbeat_interval: "30s"

# Logging (debug, info, warn, error)
log_level: "info"
```

After editing, restart the agent:

```bash
sudo systemctl restart axxon-agent
```

### Environment Variable Overrides

Any config value can be overridden with an environment variable prefixed with `AGENT_`:

```bash
# Set in /etc/systemd/system/axxon-agent.service.d/override.conf
[Service]
Environment="AGENT_AXXON_USERNAME=admin"
Environment="AGENT_AXXON_PASSWORD=secret"
Environment="AGENT_LOG_LEVEL=debug"
```

Then reload: `sudo systemctl daemon-reload && sudo systemctl restart axxon-agent`

## Troubleshooting

### Agent won't start

```bash
# Check logs for errors
sudo journalctl -u axxon-agent --no-pager -n 50

# Common issues:
# - "TLS handshake error" → Certificate mismatch. Verify ca.crt matches the gateway CA.
# - "connection refused" → Gateway not reachable. Check address and firewall.
# - "enrollment token invalid" → Token expired or already used. Generate a new one.
```

### Certificate errors

```bash
# Verify your agent cert was signed by the same CA
openssl verify -CAfile /etc/axxon-agent/ca.crt /etc/axxon-agent/agent.crt

# Check cert details
openssl x509 -in /etc/axxon-agent/agent.crt -noout -subject -issuer -dates
```

### Agent connects but shows "Unassigned"

This is normal for newly enrolled agents. An administrator needs to assign the agent to a site/server in the Agent Manager UI. Once assigned, the agent begins collecting telemetry and alarms.

### Network connectivity

```bash
# Test gateway connectivity
openssl s_client -connect axxonmonitor.digitalsecurityguard.com:18443 \
  -cert /etc/axxon-agent/agent.crt \
  -key /etc/axxon-agent/agent.key \
  -CAfile /etc/axxon-agent/ca.crt \
  </dev/null 2>&1 | grep "Verify return code"

# Expected: Verify return code: 0 (ok)
```

### Firewall

The agent makes an **outbound** connection to the gateway on port **18443** (gRPC/TLS). No inbound ports need to be opened on the agent server.

### Restart / Reset

```bash
# Restart the agent
sudo systemctl restart axxon-agent

# Full reset (clears alarm buffer and agent ID — will re-enroll)
sudo systemctl stop axxon-agent
sudo rm -f /var/lib/axxon-agent/alarms.db /etc/axxon-agent/agent-id
sudo systemctl start axxon-agent
```

## What the Agent Collects

| Category | Metrics | Interval |
|----------|---------|----------|
| AI Efficiency | IPS, FPS per detector | 30s |
| Archive Channels | Write FPS, bitrate, loss, starving status | 30s |
| System | CPU, memory, network, load averages | 30s |
| GPU | Utilization, memory usage | 30s |
| Storage | Disk usage, archive volumes, archive depth | 5 min |
| Disk Health | SMART status, temperature | 5 min |
| Services | License expiry, service state, error counts | 5 min |
| Camera Counts | Total and active cameras | 5 min |
| Alarms | Detector events with severity and acknowledgements | Continuous |

## Security

- **mTLS** — All communication is encrypted and mutually authenticated
- **CSR-based provisioning** — Private keys are generated locally and never leave the agent machine
- **Systemd hardening** — `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`
- **No inbound ports** — Agent initiates all connections outbound
- **Enrollment tokens** — Single-use, time-limited, revocable

## License

Internal tool for Techpro Security monitoring infrastructure.
