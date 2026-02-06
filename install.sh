#!/usr/bin/env bash
#
# Interactive installer for AxxonOne Monitoring Agent (Linux).
#
# Downloads the agent binary from the Artifact Portal, configures it,
# and installs as a systemd service.
#
# Usage:
#   curl -fsSL https://artifacts.digitalsecurityguard.com/install/axxon-agent.sh | sudo bash
#   # or
#   sudo ./scripts/install.sh
#
set -euo pipefail

SCRIPT_VERSION="1.3.1"

# --- Constants ---
ARTIFACT_BASE="https://artifacts.digitalsecurityguard.com/api/v2"
ORG_SLUG="axxon-monitor-site"
APP_ID="axxon-agent-installer"
PROJECT="axxon-monitor-site"
TOOL="axxon-monitor-agent"
PLATFORM_ARCH="linux-amd64"
LATEST_FILENAME="axxon-agent"
INSTALL_BIN="/usr/local/bin/axxon-agent"
CONFIG_DIR="/etc/axxon-agent"
DATA_DIR="/var/lib/axxon-agent"
SERVICE_NAME="axxon-agent"
PAIR_TIMEOUT=600  # 10 minutes (matches pairing code validity)

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }
header()  { echo -e "\n${CYAN}${BOLD}$*${NC}"; }

# --- Prerequisite checks ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (sudo)."
    fi
}

check_prerequisites() {
    local missing=()
    for cmd in curl sha256sum systemctl jq openssl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing required tools: ${missing[*]}. Install them and try again."
    fi
}

get_instance_id() {
    if [ -f /etc/machine-id ]; then
        cat /etc/machine-id
    else
        hostname | sha256sum | cut -d' ' -f1
    fi
}

# --- Artifact Portal pairing ---
artifact_portal_download() {
    local instance_id
    instance_id=$(get_instance_id)
    local my_hostname
    my_hostname=$(hostname -f 2>/dev/null || hostname)

    header "Artifact Portal - Device Pairing"
    info "Starting device pairing with Artifact Portal..."

    # Step 1: Start pairing
    local pair_resp
    pair_resp=$(curl -sf --max-time 10 \
        -X POST "${ARTIFACT_BASE}/pairing/start" \
        -H "Content-Type: application/json" \
        -d "{
            \"org_slug\": \"${ORG_SLUG}\",
            \"app_id\": \"${APP_ID}\",
            \"instance_id\": \"${instance_id}\",
            \"requested_ttl_seconds\": 14400,
            \"requested_scopes\": [\"download\"],
            \"metadata\": {
                \"hostname\": \"${my_hostname}\",
                \"platform\": \"linux\",
                \"arch\": \"amd64\",
                \"label\": \"AxxonOne Agent installer\"
            }
        }" \
        2>/dev/null) || {
        warn "Could not reach Artifact Portal."
        return 1
    }

    local pairing_code pairing_url expires_in
    pairing_code=$(echo "$pair_resp" | jq -r '.pairing_code // empty')
    pairing_url=$(echo "$pair_resp" | jq -r '.pairing_url // empty')
    expires_in=$(echo "$pair_resp" | jq -r '.expires_in // 600')

    if [ -z "$pairing_code" ]; then
        warn "Unexpected response from Artifact Portal."
        return 1
    fi

    echo ""
    echo -e "  ${BOLD}Open this URL in your browser to approve this device:${NC}"
    echo -e "  ${CYAN}https://artifacts.digitalsecurityguard.com${pairing_url}${NC}"
    echo ""
    echo -e "  ${BOLD}Pairing code:${NC} ${YELLOW}${pairing_code}${NC}"
    echo -e "  ${BOLD}Expires in:${NC} ${expires_in} seconds"
    echo ""
    info "Waiting for approval..."

    # Step 2: Poll for approval
    local elapsed=0
    local exchange_token=""
    while [ $elapsed -lt $PAIR_TIMEOUT ]; do
        sleep 2
        elapsed=$((elapsed + 2))

        local status_resp
        status_resp=$(curl -sf --max-time 10 \
            "${ARTIFACT_BASE}/pairing/status/${pairing_code}" 2>/dev/null) || continue

        local status
        status=$(echo "$status_resp" | jq -r '.status // "pending"')

        if [ "$status" = "approved" ]; then
            exchange_token=$(echo "$status_resp" | jq -r '.exchange_token // empty')
            if [ -z "$exchange_token" ]; then
                warn "Approved but no exchange token received."
                return 1
            fi
            break
        elif [ "$status" = "denied" ]; then
            warn "Pairing request was denied."
            return 1
        elif [ "$status" = "expired" ] || [ "$status" = "exchanged" ]; then
            warn "Pairing request ${status}."
            return 1
        fi

        printf "\r  Waiting... %ds / %ds" "$elapsed" "$PAIR_TIMEOUT"
    done
    echo ""

    if [ -z "$exchange_token" ]; then
        warn "Pairing timed out."
        return 1
    fi

    info "Approved! Exchanging for access token..."

    # Step 3: Exchange for access token
    local exchange_resp access_token
    exchange_resp=$(curl -sf --max-time 10 \
        -X POST "${ARTIFACT_BASE}/pairing/exchange" \
        -H "Content-Type: application/json" \
        -d "{
            \"pairing_code\": \"${pairing_code}\",
            \"exchange_token\": \"${exchange_token}\"
        }" \
        2>/dev/null) || {
        warn "Token exchange failed."
        return 1
    }
    access_token=$(echo "$exchange_resp" | jq -r '.access_token // empty')

    if [ -z "$access_token" ]; then
        warn "No access token received."
        return 1
    fi

    info "Token received. Downloading agent binary..."

    # Step 4: Get presigned download URL
    local presign_resp
    presign_resp=$(curl -sf --max-time 10 \
        -X POST "${ARTIFACT_BASE}/presign-latest" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${access_token}" \
        -d "{
            \"project\": \"${PROJECT}\",
            \"tool\": \"${TOOL}\",
            \"platform_arch\": \"${PLATFORM_ARCH}\",
            \"latest_filename\": \"${LATEST_FILENAME}\"
        }" \
        2>/dev/null) || {
        warn "Failed to get download URL."
        return 1
    }

    local download_url expected_sha256 file_size
    download_url=$(echo "$presign_resp" | jq -r '.url // empty')
    expected_sha256=$(echo "$presign_resp" | jq -r '.sha256 // empty')
    file_size=$(echo "$presign_resp" | jq -r '.size_bytes // "unknown"')

    if [ -z "$download_url" ]; then
        warn "No download URL returned. The binary may not be available for ${PLATFORM_ARCH}."
        return 1
    fi

    info "Downloading (${file_size} bytes)..."

    # Step 5: Download binary
    local tmp_bin
    tmp_bin=$(mktemp)
    if ! curl -fSL --max-time 300 -o "$tmp_bin" "$download_url" 2>/dev/null; then
        rm -f "$tmp_bin"
        warn "Download failed."
        return 1
    fi

    # Step 6: SHA256 verification
    if [ -n "$expected_sha256" ]; then
        local actual_sha256
        actual_sha256=$(sha256sum "$tmp_bin" | cut -d' ' -f1)
        if [ "$actual_sha256" != "$expected_sha256" ]; then
            rm -f "$tmp_bin"
            error "SHA256 mismatch! Expected: ${expected_sha256}, Got: ${actual_sha256}"
        fi
        info "SHA256 verified."
    fi

    # Install binary
    mv "$tmp_bin" "$INSTALL_BIN"
    chmod 755 "$INSTALL_BIN"
    info "Binary installed to $INSTALL_BIN"
    return 0
}

# --- API token download (alternative to pairing) ---
api_token_download() {
    local token="$1"

    info "Downloading agent binary using API token..."

    local presign_resp
    presign_resp=$(curl -sf --max-time 10 \
        -X POST "${ARTIFACT_BASE}/presign-latest" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${token}" \
        -d "{
            \"project\": \"${PROJECT}\",
            \"tool\": \"${TOOL}\",
            \"platform_arch\": \"${PLATFORM_ARCH}\",
            \"latest_filename\": \"${LATEST_FILENAME}\"
        }" \
        2>/dev/null) || {
        warn "Failed to get download URL. Check your API token."
        return 1
    }

    local download_url expected_sha256
    download_url=$(echo "$presign_resp" | jq -r '.url // empty')
    expected_sha256=$(echo "$presign_resp" | jq -r '.sha256 // empty')

    if [ -z "$download_url" ]; then
        warn "No download URL returned."
        return 1
    fi

    local tmp_bin
    tmp_bin=$(mktemp)
    if ! curl -fSL --max-time 300 -o "$tmp_bin" "$download_url" 2>/dev/null; then
        rm -f "$tmp_bin"
        warn "Download failed."
        return 1
    fi

    if [ -n "$expected_sha256" ]; then
        local actual_sha256
        actual_sha256=$(sha256sum "$tmp_bin" | cut -d' ' -f1)
        if [ "$actual_sha256" != "$expected_sha256" ]; then
            rm -f "$tmp_bin"
            error "SHA256 mismatch! Expected: ${expected_sha256}, Got: ${actual_sha256}"
        fi
        info "SHA256 verified."
    fi

    mv "$tmp_bin" "$INSTALL_BIN"
    chmod 755 "$INSTALL_BIN"
    info "Binary installed to $INSTALL_BIN"
    return 0
}

# --- Manual install fallback ---
show_manual_instructions() {
    echo ""
    warn "Automatic download from Artifact Portal is not available."
    echo ""
    echo "  Manual install steps:"
    echo "  1. Download the agent binary from the Artifact Portal"
    echo "     https://artifacts.digitalsecurityguard.com"
    echo "  2. Copy it to: $INSTALL_BIN"
    echo "  3. Make it executable: chmod +x $INSTALL_BIN"
    echo "  4. Re-run this script to complete configuration"
    echo ""
}

# --- TLS Certificate Provisioning via CSR ---
provision_certificates() {
    local gateway_addr="$1"
    local enrollment_token="$2"

    # Skip if certs already exist
    if [ -f "$CONFIG_DIR/agent.crt" ] && [ -f "$CONFIG_DIR/agent.key" ] && [ -f "$CONFIG_DIR/ca.crt" ]; then
        info "TLS certificates already exist in $CONFIG_DIR — skipping provisioning."
        return 0
    fi

    # Need an enrollment token for CSR provisioning
    if [ -z "$enrollment_token" ]; then
        warn "No enrollment token provided — cannot auto-provision certificates."
        return 1
    fi

    header "TLS Certificate Provisioning"
    info "Generating private key locally (key never leaves this machine)..."

    mkdir -p "$CONFIG_DIR"

    # Generate RSA private key
    if ! openssl genrsa -out "$CONFIG_DIR/agent.key" 2048 2>/dev/null; then
        warn "Failed to generate private key."
        rm -f "$CONFIG_DIR/agent.key"
        return 1
    fi
    chmod 600 "$CONFIG_DIR/agent.key"

    # Generate CSR (in variable, not saved to disk)
    local csr
    csr=$(openssl req -new \
        -key "$CONFIG_DIR/agent.key" \
        -subj "/O=TechPro Security/CN=axxon-agent" \
        2>/dev/null) || {
        warn "Failed to generate CSR."
        rm -f "$CONFIG_DIR/agent.key"
        return 1
    }

    # Derive HTTPS URL from gateway address
    # gateway_addr is host:port (e.g., axxonmonitor.digitalsecurityguard.com:18443)
    local gw_host
    gw_host=$(echo "$gateway_addr" | sed 's/:[0-9]*$//')
    local provision_url="https://${gw_host}/api/agent-provision/provision-cert"

    info "Requesting signed certificate from gateway..."
    info "  URL: ${provision_url}"

    # Build JSON payload (escape newlines in CSR for JSON)
    local csr_escaped
    csr_escaped=$(echo "$csr" | jq -Rs .)

    local resp
    resp=$(curl -sf --max-time 15 \
        -X POST "$provision_url" \
        -H "Content-Type: application/json" \
        -d "{\"token\": \"${enrollment_token}\", \"csr\": ${csr_escaped}}" \
        2>/dev/null) || {
        warn "Could not reach gateway for certificate provisioning."
        rm -f "$CONFIG_DIR/agent.key"
        return 1
    }

    # Check for errors in response
    local resp_error
    resp_error=$(echo "$resp" | jq -r '.error // empty')
    if [ -n "$resp_error" ]; then
        warn "Certificate provisioning failed: ${resp_error}"
        rm -f "$CONFIG_DIR/agent.key"
        return 1
    fi

    # Extract certificate and CA chain
    local cert ca_chain expires
    cert=$(echo "$resp" | jq -r '.certificate // empty')
    ca_chain=$(echo "$resp" | jq -r '.ca_chain // empty')
    expires=$(echo "$resp" | jq -r '.expires // "unknown"')

    if [ -z "$cert" ] || [ -z "$ca_chain" ]; then
        warn "Incomplete response from gateway (missing certificate or CA chain)."
        rm -f "$CONFIG_DIR/agent.key"
        return 1
    fi

    # Write certificate files
    echo "$cert" > "$CONFIG_DIR/agent.crt"
    echo "$ca_chain" > "$CONFIG_DIR/ca.crt"
    chmod 644 "$CONFIG_DIR/agent.crt" "$CONFIG_DIR/ca.crt"

    info "TLS certificates provisioned successfully!"
    info "  Certificate expires: ${expires}"
    info "  Private key: $CONFIG_DIR/agent.key"
    info "  Certificate: $CONFIG_DIR/agent.crt"
    info "  CA chain:    $CONFIG_DIR/ca.crt"
    return 0
}

install_certificates_manual() {
    echo ""
    warn "Automatic certificate provisioning not available."
    echo ""
    echo "  Please copy TLS certificates to $CONFIG_DIR/:"
    echo "    agent.crt  - Agent certificate"
    echo "    agent.key  - Agent private key"
    echo "    ca.crt     - CA chain"
    echo ""
    echo "  Then restart the agent:"
    echo "    sudo systemctl restart $SERVICE_NAME"
    echo ""
}

# --- Configuration ---
configure_agent() {
    local gateway_addr="$1"
    local enrollment_token="$2"

    mkdir -p "$CONFIG_DIR" "$DATA_DIR"

    if [ -f "$CONFIG_DIR/config.yaml" ]; then
        warn "Config already exists at $CONFIG_DIR/config.yaml — not overwriting."
        return
    fi

    local identity_line=""
    if [ -n "$enrollment_token" ]; then
        identity_line="enrollment_token: \"${enrollment_token}\""
    else
        identity_line="# agent_id: \"my-agent\"  # Set manually or use enrollment_token"
    fi

    cat > "$CONFIG_DIR/config.yaml" <<EOF
gateway_addr: "${gateway_addr}"
${identity_line}
agent_id_file: "/etc/axxon-agent/agent-id"
cert_file: "/etc/axxon-agent/agent.crt"
key_file: "/etc/axxon-agent/agent.key"
ca_file: "/etc/axxon-agent/ca.crt"
axxon_port: 80
alarm_db_path: "/var/lib/axxon-agent/alarms.db"
heartbeat_interval: "30s"
log_level: "info"
EOF

    chmod 640 "$CONFIG_DIR/config.yaml"
    info "Config created at $CONFIG_DIR/config.yaml"
}

install_systemd_service() {
    cat > "/lib/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=AxxonOne Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/axxon-agent --config /etc/axxon-agent/config.yaml
Restart=always
RestartSec=10
User=root
WorkingDirectory=/var/lib/axxon-agent

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/axxon-agent
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    info "Systemd service installed and enabled."
}

# --- Main ---
main() {
    echo "============================================"
    echo "  AxxonOne Agent - Interactive Installer"
    echo "  Version: ${SCRIPT_VERSION}"
    echo "============================================"
    echo ""

    check_root
    check_prerequisites

    info "Platform: ${PLATFORM_ARCH}"

    # Prompt for gateway address
    header "Configuration"
    local gateway_addr=""
    read -rp "  Gateway address (host:port) [gateway:18443]: " gateway_addr </dev/tty
    gateway_addr="${gateway_addr:-gateway:18443}"

    # Prompt for enrollment token
    local enrollment_token=""
    read -rp "  Enrollment token (optional, press Enter to skip): " enrollment_token </dev/tty

    # Download binary
    if [ ! -f "$INSTALL_BIN" ]; then
        header "Download Agent Binary"
        echo ""
        echo "  Choose download method:"
        echo "    1) Device pairing (opens browser for approval)"
        echo "    2) API token (paste a pre-created apt_... token)"
        echo "    3) Skip (binary already installed or manual install)"
        echo ""
        local download_method=""
        read -rp "  Method [1]: " download_method </dev/tty
        download_method="${download_method:-1}"

        case "$download_method" in
            1)
                if ! artifact_portal_download; then
                    show_manual_instructions
                    if [ ! -f "$INSTALL_BIN" ]; then
                        error "Agent binary not found at $INSTALL_BIN. Install it manually and re-run."
                    fi
                fi
                ;;
            2)
                local api_token=""
                read -rp "  API token: " api_token </dev/tty
                if [ -z "$api_token" ]; then
                    error "API token is required."
                fi
                if ! api_token_download "$api_token"; then
                    show_manual_instructions
                    if [ ! -f "$INSTALL_BIN" ]; then
                        error "Agent binary not found at $INSTALL_BIN. Install it manually and re-run."
                    fi
                fi
                ;;
            3)
                if [ ! -f "$INSTALL_BIN" ]; then
                    show_manual_instructions
                    error "Agent binary not found at $INSTALL_BIN. Install it manually and re-run."
                fi
                ;;
            *)
                error "Invalid choice."
                ;;
        esac
    else
        info "Agent binary already exists at $INSTALL_BIN"
    fi

    # Provision TLS certificates via CSR (with manual fallback)
    if ! provision_certificates "$gateway_addr" "$enrollment_token"; then
        install_certificates_manual
    fi

    # Configure
    configure_agent "$gateway_addr" "$enrollment_token"

    # Install service
    install_systemd_service

    # Start
    header "Starting Agent"
    systemctl start "$SERVICE_NAME" || warn "Failed to start agent. Check config and certs."

    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        info "Agent is running!"
    else
        warn "Agent may not be running. Check logs with: sudo journalctl -u $SERVICE_NAME -f"
    fi

    echo ""
    info "Installation complete!"
    echo ""
    echo "  Status:  sudo systemctl status $SERVICE_NAME"
    echo "  Logs:    sudo journalctl -u $SERVICE_NAME -f"
    echo "  Config:  $CONFIG_DIR/config.yaml"
    echo ""
}

main "$@"
