# AxxonOne Monitoring Agent

Lightweight monitoring agent for AxxonOne VMS servers. Collects telemetry (CPU, GPU, storage, AI efficiency metrics), alarm events, and provides API proxy capabilities — all reported back to a central gateway over gRPC with mTLS encryption.

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh | sudo bash
```

The installer will prompt you for:
1. **Gateway address** — the central monitoring server (default: `axxonmonitor.digitalsecurityguard.com:18443`)
2. **Enrollment token** — optional one-time token from the gateway admin
3. **TLS certificates** — path to certificate files for mTLS authentication

## Prerequisites

- Linux (amd64 or arm64)
- `curl`, `sha256sum`, `systemctl`
- Network access to the gateway on port 18443
- TLS certificates from your gateway administrator

## Installation

### Step 1: Get TLS Certificates

Before installing, obtain these 3 files from your gateway administrator:

| File | Description |
|------|-------------|
| `agent.crt` | Agent TLS certificate |
| `agent.key` | Agent private key |
| `ca.crt` | CA certificate chain |

Place them in a directory (e.g., `/tmp/agent-certs/`).

### Step 2: Get an Enrollment Token (Optional)

If your gateway requires enrollment, ask your administrator to generate a token from the Agent Manager UI. Tokens are single-use and valid for 24 hours.

### Step 3: Run the Installer

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
2. Download the agent binary (Artifact Portal with device pairing, or GitHub releases as fallback)
3. Verify the SHA256 checksum
4. Install TLS certificates
5. Create configuration at `/etc/axxon-agent/config.yaml`
6. Install and start the systemd service

### Step 4: Verify

```bash
# Check service status
sudo systemctl status axxon-agent

# Watch logs
sudo journalctl -u axxon-agent -f
```

The agent should connect to the gateway and appear in the Agent Manager UI.

## Upgrade

Upgrade to the latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh | sudo bash -s -- --upgrade
```

Or if you have the script locally:

```bash
sudo ./install.sh --upgrade
```

This downloads the latest binary and restarts the service. Configuration is preserved.

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh | sudo bash -s -- --uninstall
```

This stops the service and removes the binary. Configuration and data directories are preserved (remove manually if desired).

## File Locations

| Path | Description |
|------|-------------|
| `/usr/local/bin/axxon-agent` | Agent binary |
| `/etc/axxon-agent/config.yaml` | Configuration file |
| `/etc/axxon-agent/agent.crt` | Agent TLS certificate |
| `/etc/axxon-agent/agent.key` | Agent private key |
| `/etc/axxon-agent/ca.crt` | CA certificate chain |
| `/etc/axxon-agent/agent-id` | Assigned agent ID (auto-generated) |
| `/var/lib/axxon-agent/alarms.db` | Local alarm buffer (SQLite) |

## Configuration

Edit `/etc/axxon-agent/config.yaml`:

```yaml
# Gateway connection
gateway_addr: "axxonmonitor.digitalsecurityguard.com:18443"

# Identity (one of these)
enrollment_token: "enroll_..."    # First-time enrollment
# agent_id: "uuid-here"          # Or set directly

# TLS certificates
cert_file: "/etc/axxon-agent/agent.crt"
key_file: "/etc/axxon-agent/agent.key"
ca_file: "/etc/axxon-agent/ca.crt"

# AxxonOne server (local connection)
axxon_port: 80                    # AxxonOne HTTP API port
# axxon_username: ""              # Set via AGENT_AXXON_USERNAME env var
# axxon_password: ""              # Set via AGENT_AXXON_PASSWORD env var

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

### Agent connects but shows "Pending"

This is normal. An administrator needs to assign the agent to a site/server in the Agent Manager UI. Once assigned, the agent will begin collecting telemetry and alarms.

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

The agent makes an **outbound** connection to the gateway on port **18443** (gRPC/TLS). Ensure this port is open for outbound traffic. No inbound ports need to be opened on the agent server.

### Restart / Reset

```bash
# Restart the agent
sudo systemctl restart axxon-agent

# Full reset (clears alarm buffer and agent ID)
sudo systemctl stop axxon-agent
sudo rm -f /var/lib/axxon-agent/alarms.db /etc/axxon-agent/agent-id
sudo systemctl start axxon-agent
```

## What the Agent Collects

| Category | Metrics | Interval |
|----------|---------|----------|
| AI Efficiency | IPS, FPS per detector | 30s |
| Archive | Write speed, depth, usage | 30s |
| System | CPU, memory, network, load | 30s |
| GPU | Utilization, memory, temperature (via NVML) | 30s |
| Storage | Disk usage, archive volumes | 30s |
| Services | License expiry, service state, errors | 5 min |
| Alarms | Detector events with clustering | Hourly fetch |

## License

Internal tool for Techpro Security monitoring infrastructure.
