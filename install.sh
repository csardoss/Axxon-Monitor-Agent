#!/usr/bin/env bash
#
# Interactive installer for AxxonOne Monitoring Agent (Linux).
#
# Downloads the agent binary from GitHub releases, configures it,
# and installs as a systemd service.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/csardoss/Axxon-Monitor-Agent/main/install.sh | sudo bash
#   # or
#   sudo ./install.sh
#
set -euo pipefail

# --- Constants ---
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
    info "Platform: ${PLATFORM}"
}

# --- GitHub release download ---
download_latest_release() {
    header "Download Agent Binary"

    info "Fetching latest release from GitHub..."

    # Get latest release info
    local release_json
    release_json=$(curl -sf --max-time 15 "${GITHUB_API}/releases/latest" 2>/dev/null) || {
        error "Could not fetch latest release from GitHub. Check network connectivity."
    }

    local tag_name
    tag_name=$(echo "$release_json" | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$tag_name" ]; then
        error "No releases found. Please check ${GITHUB_API}/releases"
    fi

    info "Latest version: ${tag_name}"

    # Find the binary asset for our platform
    local asset_name="axxon-agent-${PLATFORM}"
    local sha_name="${asset_name}.sha256"

    local download_url
    download_url=$(echo "$release_json" | grep -o "\"browser_download_url\":\"[^\"]*${asset_name}\"" | head -1 | cut -d'"' -f4)

    if [ -z "$download_url" ]; then
        error "No binary found for platform '${PLATFORM}' in release ${tag_name}."
    fi

    local sha_url
    sha_url=$(echo "$release_json" | grep -o "\"browser_download_url\":\"[^\"]*${sha_name}\"" | head -1 | cut -d'"' -f4)

    # Download binary
    info "Downloading ${asset_name}..."
    local tmp_bin
    tmp_bin=$(mktemp)
    if ! curl -fSL --max-time 300 -o "$tmp_bin" "$download_url" 2>/dev/null; then
        rm -f "$tmp_bin"
        error "Download failed. URL: $download_url"
    fi

    # SHA256 verification
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
    else
        warn "No checksum file found in release. Skipping verification."
    fi

    # Install binary
    mv "$tmp_bin" "$INSTALL_BIN"
    chmod 755 "$INSTALL_BIN"
    info "Binary installed to $INSTALL_BIN (${tag_name})"
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
    read -rp "  Path to certificate directory (or press Enter to skip): " cert_source

    if [ -n "$cert_source" ]; then
        cert_source="${cert_source%/}"  # strip trailing slash

        local missing=()
        [ -f "$cert_source/agent.crt" ] || missing+=("agent.crt")
        [ -f "$cert_source/agent.key" ] || missing+=("agent.key")
        # Accept either ca.crt or chain.crt
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

    local current_version=""
    current_version=$("$INSTALL_BIN" --version 2>/dev/null || echo "unknown")
    info "Current version: ${current_version}"

    download_latest_release

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
    read -rp "  This will stop and remove the agent. Continue? [y/N]: " confirm
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
    # Handle flags
    case "${1:-}" in
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
            echo "AxxonOne Monitoring Agent Installer"
            echo ""
            echo "Usage:"
            echo "  sudo ./install.sh              Install the agent (interactive)"
            echo "  sudo ./install.sh --upgrade    Upgrade to latest version"
            echo "  sudo ./install.sh --uninstall  Remove the agent"
            echo "  sudo ./install.sh --help       Show this help"
            exit 0
            ;;
    esac

    echo "============================================"
    echo "  AxxonOne Agent - Interactive Installer"
    echo "============================================"
    echo ""

    check_root
    check_prerequisites
    detect_platform

    # Prompt for gateway address
    header "Configuration"
    local gateway_addr=""
    read -rp "  Gateway address (host:port) [axxonmonitor.digitalsecurityguard.com:18443]: " gateway_addr
    gateway_addr="${gateway_addr:-axxonmonitor.digitalsecurityguard.com:18443}"

    # Prompt for enrollment token
    local enrollment_token=""
    read -rp "  Enrollment token (optional, press Enter to skip): " enrollment_token

    # Download binary
    if [ -f "$INSTALL_BIN" ]; then
        echo ""
        read -rp "  Agent binary already exists. Reinstall? [y/N]: " reinstall
        if [[ "$reinstall" =~ ^[Yy]$ ]]; then
            download_latest_release
        else
            info "Keeping existing binary."
        fi
    else
        download_latest_release
    fi

    # Install certificates
    install_certificates

    # Configure
    configure_agent "$gateway_addr" "$enrollment_token"

    # Install service
    install_systemd_service

    # Start
    header "Starting Agent"

    # Check if certs exist before starting
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
    echo "    Upgrade:  curl -fsSL https://raw.githubusercontent.com/${GITHUB_REPO}/main/install.sh | sudo bash -s -- --upgrade"
    echo ""
}

main "$@"
