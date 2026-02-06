#!/usr/bin/env bash
#
# Interactive installer for AxxonOne Monitoring Agent (Linux).
#
# Downloads the agent binary via:
#   1. Artifact Portal (device pairing) — primary
#   2. GitHub releases — fallback
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh | sudo bash
#   # or
#   sudo ./install.sh
#
set -euo pipefail

# --- Script Version ---
SCRIPT_VERSION="1.1.0"

# --- Constants ---
ARTIFACT_BASE="https://artifacts.digitalsecurityguard.com/api/v2"
ORG_SLUG="axxon-monitor-site"
APP_ID="axxon-agent-installer"
PROJECT="axxon-monitor-site"
TOOL="axxon-monitor-agent"
PAIR_TIMEOUT=600  # 10 minutes

GITHUB_REPO="csardoss/Axxon-Monitor-Agent"
GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}"

INSTALL_BIN="/usr/local/bin/axxon-agent"
CONFIG_DIR="/etc/axxon-agent"
DATA_DIR="/var/lib/axxon-agent"
SERVICE_NAME="axxon-agent"

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

# Read from /dev/tty so prompts work when piped via curl | bash
prompt()  { read -rp "$1" "$2" </dev/tty; }

# --- Prerequisite checks ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error "This script must be run as root (sudo)."
    fi
}

check_prerequisites() {
    local missing=()
    for cmd in curl sha256sum systemctl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        error "Missing required tools: ${missing[*]}. Install them and try again."
    fi
}

detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)

    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       error "Unsupported architecture: $arch" ;;
    esac

    if [ "$os" != "linux" ]; then
        error "This installer only supports Linux. Detected: $os"
    fi

    PLATFORM="${os}-${arch}"
    PLATFORM_ARCH="${os}-${arch}"
    info "Platform: ${PLATFORM}"
}

get_instance_id() {
    if [ -f /etc/machine-id ]; then
        cat /etc/machine-id
    else
        hostname | sha256sum | cut -d' ' -f1
    fi
}

# ===========================================================================
# Download Method 1: Artifact Portal (device pairing)
# ===========================================================================
artifact_portal_download() {
    local instance_id
    instance_id=$(get_instance_id)
    local my_hostname
    my_hostname=$(hostname -f 2>/dev/null || hostname)

    header "Artifact Portal — Device Pairing"
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
                \"arch\": \"$(uname -m)\",
                \"label\": \"AxxonOne Agent installer\"
            }
        }" \
        2>/dev/null) || {
        warn "Could not reach Artifact Portal."
        return 1
    }

    local pairing_code pairing_url expires_in
    pairing_code=$(echo "$pair_resp" | grep -o '"pairing_code":"[^"]*"' | head -1 | cut -d'"' -f4)
    pairing_url=$(echo "$pair_resp" | grep -o '"pairing_url":"[^"]*"' | head -1 | cut -d'"' -f4)
    expires_in=$(echo "$pair_resp" | grep -o '"expires_in":[0-9]*' | head -1 | cut -d: -f2)
    expires_in="${expires_in:-600}"

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
        status=$(echo "$status_resp" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

        if [ "$status" = "approved" ]; then
            exchange_token=$(echo "$status_resp" | grep -o '"exchange_token":"[^"]*"' | head -1 | cut -d'"' -f4)
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
    access_token=$(echo "$exchange_resp" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4)

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
            \"latest_filename\": \"axxon-agent\"
        }" \
        2>/dev/null) || {
        warn "Failed to get download URL."
        return 1
    }

    local download_url expected_sha256 file_size
    download_url=$(echo "$presign_resp" | grep -o '"url":"[^"]*"' | head -1 | cut -d'"' -f4)
    expected_sha256=$(echo "$presign_resp" | grep -o '"sha256":"[^"]*"' | head -1 | cut -d'"' -f4)
    file_size=$(echo "$presign_resp" | grep -o '"size_bytes":[0-9]*' | head -1 | cut -d: -f2)
    file_size="${file_size:-unknown}"

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
    info "Binary installed to $INSTALL_BIN (via Artifact Portal)"
    return 0
}

# ===========================================================================
# Download Method 2: GitHub Releases (fallback)
# ===========================================================================
github_release_download() {
    header "GitHub Releases — Fallback Download"

    info "Fetching latest release from GitHub..."

    local release_json
    release_json=$(curl -sf --max-time 15 "${GITHUB_API}/releases/latest" 2>/dev/null) || {
        warn "Could not fetch latest release from GitHub."
        return 1
    }

    local tag_name
    tag_name=$(echo "$release_json" | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$tag_name" ]; then
        warn "No releases found on GitHub."
        return 1
    fi

    info "Latest version: ${tag_name}"

    local asset_name="axxon-agent-${PLATFORM}"
    local sha_name="${asset_name}.sha256"

    local download_url
    download_url=$(echo "$release_json" | grep -o "\"browser_download_url\":\"[^\"]*${asset_name}\"" | head -1 | cut -d'"' -f4)

    if [ -z "$download_url" ]; then
        warn "No binary found for platform '${PLATFORM}' in release ${tag_name}."
        return 1
    fi

    local sha_url
    sha_url=$(echo "$release_json" | grep -o "\"browser_download_url\":\"[^\"]*${sha_name}\"" | head -1 | cut -d'"' -f4)

    info "Downloading ${asset_name}..."
    local tmp_bin
    tmp_bin=$(mktemp)
    if ! curl -fSL --max-time 300 -o "$tmp_bin" "$download_url" 2>/dev/null; then
        rm -f "$tmp_bin"
        warn "Download failed."
        return 1
    fi

    if [ -n "$sha_url" ]; then
        info "Verifying SHA256 checksum..."
        local expected_sha
        expected_sha=$(curl -sf --max-time 10 "$sha_url" 2>/dev/null | awk '{print $1}')
        if [ -n "$expected_sha" ]; then
            local actual_sha
            actual_sha=$(sha256sum "$tmp_bin" | awk '{print $1}')
            if [ "$actual_sha" != "$expected_sha" ]; then
                rm -f "$tmp_bin"
                error "SHA256 mismatch!\n  Expected: ${expected_sha}\n  Got:      ${actual_sha}"
            fi
            info "SHA256 verified."
        else
            warn "Could not fetch checksum file. Skipping verification."
        fi
    fi

    mv "$tmp_bin" "$INSTALL_BIN"
    chmod 755 "$INSTALL_BIN"
    info "Binary installed to $INSTALL_BIN (${tag_name}, via GitHub)"
    return 0
}

# ===========================================================================
# Download orchestrator — tries methods in order
# ===========================================================================
download_agent_binary() {
    header "Download Agent Binary"

    echo ""
    echo "  Choose download method:"
    echo "    1) Artifact Portal (device pairing — recommended)"
    echo "    2) GitHub releases (direct download)"
    echo "    3) Skip (binary already installed manually)"
    echo ""
    local download_method=""
    prompt "  Method [1]: " download_method
    download_method="${download_method:-1}"

    case "$download_method" in
        1)
            if ! artifact_portal_download; then
                echo ""
                warn "Artifact Portal download failed."
                prompt "  Try GitHub releases as fallback? [Y/n]: " use_fallback
                if [[ ! "$use_fallback" =~ ^[Nn]$ ]]; then
                    if ! github_release_download; then
                        error "All download methods failed. Install the binary manually to $INSTALL_BIN"
                    fi
                else
                    error "Agent binary not available. Install it manually to $INSTALL_BIN"
                fi
            fi
            ;;
        2)
            if ! github_release_download; then
                error "GitHub release download failed. Check network connectivity."
            fi
            ;;
        3)
            if [ ! -f "$INSTALL_BIN" ]; then
                error "Agent binary not found at $INSTALL_BIN. Install it manually and re-run."
            fi
            info "Using existing binary at $INSTALL_BIN"
            ;;
        *)
            error "Invalid choice."
            ;;
    esac
}

# --- TLS Certificate Installation ---
install_certificates() {
    header "TLS Certificates"

    mkdir -p "$CONFIG_DIR"

    if [ -f "$CONFIG_DIR/agent.crt" ] && [ -f "$CONFIG_DIR/agent.key" ] && [ -f "$CONFIG_DIR/ca.crt" ]; then
        info "Certificates already exist in $CONFIG_DIR/ — skipping."
        return
    fi

    echo ""
    echo "  The agent requires TLS certificates for mTLS with the gateway."
    echo "  You need 3 files from your gateway administrator:"
    echo ""
    echo "    1. agent.crt  - Agent certificate"
    echo "    2. agent.key  - Agent private key"
    echo "    3. ca.crt     - CA certificate chain"
    echo ""

    local cert_source=""
    prompt "  Path to certificate directory (or press Enter to skip): " cert_source

    if [ -n "$cert_source" ]; then
        cert_source="${cert_source%/}"

        local missing=()
        [ -f "$cert_source/agent.crt" ] || missing+=("agent.crt")
        [ -f "$cert_source/agent.key" ] || missing+=("agent.key")
        local ca_file=""
        if [ -f "$cert_source/ca.crt" ]; then
            ca_file="ca.crt"
        elif [ -f "$cert_source/chain.crt" ]; then
            ca_file="chain.crt"
        else
            missing+=("ca.crt or chain.crt")
        fi

        if [ ${#missing[@]} -gt 0 ]; then
            warn "Missing files in $cert_source: ${missing[*]}"
            warn "Skipping certificate install. Copy them manually to $CONFIG_DIR/"
            return
        fi

        cp "$cert_source/agent.crt" "$CONFIG_DIR/agent.crt"
        cp "$cert_source/agent.key" "$CONFIG_DIR/agent.key"
        cp "$cert_source/$ca_file"  "$CONFIG_DIR/ca.crt"
        chmod 644 "$CONFIG_DIR/agent.crt" "$CONFIG_DIR/ca.crt"
        chmod 600 "$CONFIG_DIR/agent.key"
        info "Certificates installed to $CONFIG_DIR/"
    else
        warn "Skipping certificate install."
        warn "Copy agent.crt, agent.key, and ca.crt to $CONFIG_DIR/ before starting."
    fi
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
# AxxonOne Monitoring Agent Configuration
# Generated by install.sh on $(date -u '+%Y-%m-%d %H:%M:%S UTC')

gateway_addr: "${gateway_addr}"
${identity_line}
agent_id_file: "${CONFIG_DIR}/agent-id"

# TLS certificates
cert_file: "${CONFIG_DIR}/agent.crt"
key_file: "${CONFIG_DIR}/agent.key"
ca_file: "${CONFIG_DIR}/ca.crt"

# AxxonOne server (local)
axxon_port: 80

# Alarm buffer
alarm_db_path: "${DATA_DIR}/alarms.db"

# Timing
heartbeat_interval: "30s"

# Logging
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

# --- Upgrade ---
upgrade_agent() {
    header "Upgrading Agent"

    if [ ! -f "$INSTALL_BIN" ]; then
        error "Agent not installed. Run this script without --upgrade first."
    fi

    info "Downloading latest version..."

    # For upgrades, try GitHub first (simpler, no pairing needed)
    if ! github_release_download; then
        warn "GitHub download failed, trying Artifact Portal..."
        if ! artifact_portal_download; then
            error "All download methods failed."
        fi
    fi

    info "Restarting agent..."
    systemctl restart "$SERVICE_NAME" 2>/dev/null || warn "Could not restart service."

    sleep 2
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        info "Agent upgraded and running!"
    else
        warn "Agent may not be running. Check: journalctl -u $SERVICE_NAME"
    fi
}

# --- Uninstall ---
uninstall_agent() {
    header "Uninstalling Agent"

    echo ""
    prompt "  This will stop and remove the agent. Continue? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Cancelled."
        exit 0
    fi

    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/lib/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true

    rm -f "$INSTALL_BIN"
    info "Agent uninstalled."

    echo ""
    echo "  Config and data directories were NOT removed:"
    echo "    Config: $CONFIG_DIR/"
    echo "    Data:   $DATA_DIR/"
    echo ""
    echo "  To remove them: sudo rm -rf $CONFIG_DIR $DATA_DIR"
}

# --- Main ---
main() {
    case "${1:-}" in
        --version|-v)
            echo "install.sh version ${SCRIPT_VERSION}"
            exit 0
            ;;
        --upgrade|-u)
            check_root
            check_prerequisites
            detect_platform
            upgrade_agent
            exit 0
            ;;
        --uninstall|--remove)
            check_root
            uninstall_agent
            exit 0
            ;;
        --help|-h)
            echo "AxxonOne Monitoring Agent Installer v${SCRIPT_VERSION}"
            echo ""
            echo "Usage:"
            echo "  sudo ./install.sh              Install the agent (interactive)"
            echo "  sudo ./install.sh --upgrade    Upgrade to latest version"
            echo "  sudo ./install.sh --uninstall  Remove the agent"
            echo "  sudo ./install.sh --version    Show script version"
            echo "  sudo ./install.sh --help       Show this help"
            exit 0
            ;;
    esac

    echo "============================================"
    echo "  AxxonOne Agent — Interactive Installer"
    echo "  Script version: ${SCRIPT_VERSION}"
    echo "============================================"
    echo ""

    check_root
    check_prerequisites
    detect_platform

    # Prompt for gateway address
    header "Configuration"
    local gateway_addr=""
    prompt "  Gateway address (host:port) [axxonmonitor.digitalsecurityguard.com:18443]: " gateway_addr
    gateway_addr="${gateway_addr:-axxonmonitor.digitalsecurityguard.com:18443}"

    # Prompt for enrollment token
    local enrollment_token=""
    prompt "  Enrollment token (optional, press Enter to skip): " enrollment_token

    # Download binary
    if [ -f "$INSTALL_BIN" ]; then
        echo ""
        prompt "  Agent binary already exists. Reinstall? [y/N]: " reinstall
        if [[ "$reinstall" =~ ^[Yy]$ ]]; then
            download_agent_binary
        else
            info "Keeping existing binary."
        fi
    else
        download_agent_binary
    fi

    # Install certificates
    install_certificates

    # Configure
    configure_agent "$gateway_addr" "$enrollment_token"

    # Install service
    install_systemd_service

    # Start
    header "Starting Agent"

    if [ ! -f "$CONFIG_DIR/agent.crt" ] || [ ! -f "$CONFIG_DIR/agent.key" ] || [ ! -f "$CONFIG_DIR/ca.crt" ]; then
        warn "TLS certificates not found. The agent will NOT start until you install them."
        echo ""
        echo "  Copy your certificates to $CONFIG_DIR/:"
        echo "    agent.crt  - Agent certificate"
        echo "    agent.key  - Agent private key"
        echo "    ca.crt     - CA certificate chain"
        echo ""
        echo "  Then start the agent:"
        echo "    sudo systemctl start $SERVICE_NAME"
    else
        systemctl start "$SERVICE_NAME" || warn "Failed to start agent. Check config and certs."

        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            info "Agent is running!"
        else
            warn "Agent may not be running. Check logs below."
        fi
    fi

    echo ""
    info "Installation complete!"
    echo ""
    echo "  Useful commands:"
    echo "    Status:   sudo systemctl status $SERVICE_NAME"
    echo "    Logs:     sudo journalctl -u $SERVICE_NAME -f"
    echo "    Config:   $CONFIG_DIR/config.yaml"
    echo "    Upgrade:  sudo ./install.sh --upgrade"
    echo ""
}

main "$@"
