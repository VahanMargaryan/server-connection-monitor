#!/bin/bash
#===============================================================================
# Server Connection Monitor - Installation Script
#
# Monitors SSH/TTY connections and sends Telegram alerts with action buttons
#
# Usage:
#   sudo ./install.sh [command]
#
# One-line remote install / update (no checkout needed):
#   curl -fsSL https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh | sudo bash -s update
#   wget -qO- https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh | sudo bash
#
# Commands:
#   install     Fresh installation (default)
#   update      Update existing installation
#   fix         Fix duplicate notifications
#   uninstall   Remove installation
#   test        Test Telegram notification
#   status      Show service status
#
# License: MIT
#===============================================================================

set -euo pipefail

# Version
VERSION="2.1.0"

# GitHub repository for remote installation
readonly GITHUB_REPO="VahanMargaryan/server-connection-monitor"
readonly GITHUB_BRANCH="main"
readonly GITHUB_RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Paths
readonly INSTALL_DIR="/usr/local/bin"
readonly CONFIG_DIR="/etc/connection-monitor"
readonly LIB_DIR="/var/lib/connection-monitor"
readonly SYSTEMD_DIR="/etc/systemd/system"
# When piped via stdin (curl|bash) BASH_SOURCE is empty; fall back so we don't
# trip `set -u`. An unresolved SCRIPT_DIR simply triggers the GitHub download.
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || echo "/tmp")"
else
    SCRIPT_DIR="/tmp"
fi

# Script names
readonly MONITOR_SCRIPT="connection-monitor"
readonly HANDLER_SCRIPT="connection-monitor-handler"
readonly SERVICE_NAME="connection-monitor-handler"

# Non-interactive support (for `curl ... | sudo bash` and automation).
# Capture any credentials from the environment BEFORE config.conf is sourced
# (sourcing would otherwise overwrite these with the empty template values).
ENV_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
ENV_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
# ASSUME_YES=true (or no terminal available) skips all interactive prompts.
ASSUME_YES="${ASSUME_YES:-false}"

#===============================================================================
# Output Functions
#===============================================================================

print_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════╗
║         Server Connection Monitor - Installation Script          ║
║                                                                  ║
║   Monitors connections and sends Telegram alerts with controls   ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "  Version: ${CYAN}${VERSION}${NC}"
    echo ""
}

log_step() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_info() { echo -e "${BLUE}[i]${NC} $1"; }

die() {
    log_error "$1"
    exit 1
}

# Prompt for input, storing the reply in the variable named by $2.
#   ask <prompt> <var_name> [default]
# Works even when the script is piped via stdin (curl|bash): in that case the
# script body occupies stdin, so we read the answer from the controlling
# terminal /dev/tty instead. With no terminal at all (ASSUME_YES or CI), the
# default is used. Never aborts under `set -e` (read EOF is handled).
ask() {
    local prompt="$1" __var="$2" default="${3:-}" reply=""
    if [[ "$ASSUME_YES" == "true" ]]; then
        reply="$default"
    elif [[ -t 0 ]]; then
        read -rp "$prompt" reply || reply="$default"
    elif [[ -e /dev/tty ]]; then
        read -rp "$prompt" reply < /dev/tty || reply="$default"
    else
        reply="$default"
    fi
    printf -v "$__var" '%s' "$reply"
}

# Escape a value for safe use as the replacement text in `sed s|...|VALUE|`
# (escapes the '|' delimiter, '&', and backslash) so credentials containing
# those characters cannot corrupt config.conf or break the sed command.
esc_sed() {
    printf '%s' "$1" | sed 's/[&|\]/\\&/g'
}

#===============================================================================
# Validation Functions
#===============================================================================

check_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root (use sudo)"
}

check_os() {
    if [[ ! -f /etc/debian_version ]] && [[ ! -f /etc/redhat-release ]]; then
        log_warn "This script is optimized for Debian/Ubuntu/RHEL. Proceeding anyway..."
    fi
}

# True if a supported downloader (curl or wget) is available.
have_downloader() {
    command -v curl &>/dev/null || command -v wget &>/dev/null
}

# Download a URL to a file using curl or wget, whichever is present.
#   fetch <url> <output_path>
# Returns non-zero on failure (HTTP errors included) or if neither tool exists.
fetch() {
    local url="$1" out="$2"
    if command -v curl &>/dev/null; then
        curl -fsSL "$url" -o "$out"
    elif command -v wget &>/dev/null; then
        wget -q -O "$out" "$url"
    else
        return 127
    fi
}

download_remote_files() {
    log_info "Downloading files from GitHub..."

    local temp_dir
    temp_dir=$(mktemp -d)
    SCRIPT_DIR="$temp_dir"

    local files=("connection-monitor.sh" "callback-handler.sh" "config.conf.template" "connection-monitor-handler.service")

    for file in "${files[@]}"; do
        local url="${GITHUB_RAW_URL}/${file}"
        if fetch "$url" "$temp_dir/$file"; then
            log_step "Downloaded $file"
        else
            log_warn "Could not download $file (may be optional)"
        fi
    done

    # Verify required files
    if [[ ! -f "$temp_dir/connection-monitor.sh" ]] || [[ ! -f "$temp_dir/callback-handler.sh" ]]; then
        rm -rf "$temp_dir"
        die "Failed to download required files from GitHub"
    fi
}

check_source_files() {
    local missing=()
    [[ -f "$SCRIPT_DIR/connection-monitor.sh" ]] || missing+=("connection-monitor.sh")
    [[ -f "$SCRIPT_DIR/callback-handler.sh" ]] || missing+=("callback-handler.sh")

    if [[ ${#missing[@]} -gt 0 ]]; then
        # Not run from a checkout (e.g. piped via curl|bash): fetch from GitHub
        if have_downloader; then
            download_remote_files
        else
            die "Missing required files: ${missing[*]}. Install curl or wget for remote installation."
        fi
    fi
}

check_installed() {
    [[ -f "$INSTALL_DIR/$MONITOR_SCRIPT" ]] && [[ -f "$INSTALL_DIR/$HANDLER_SCRIPT" ]]
}

#===============================================================================
# Installation Functions
#===============================================================================

install_dependencies() {
    log_info "Installing dependencies..."

    local packages="curl python3 iptables iproute2"

    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        for pkg in $packages; do
            if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
                apt-get install -y -qq "$pkg" && log_step "Installed $pkg"
            else
                log_step "$pkg already installed"
            fi
        done
        # Optional: iptables-persistent
        if ! dpkg -l iptables-persistent 2>/dev/null | grep -q "^ii"; then
            log_info "Installing iptables-persistent..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent 2>/dev/null || true
        fi
    elif command -v yum &>/dev/null; then
        for pkg in $packages; do
            if ! rpm -q "$pkg" &>/dev/null; then
                yum install -y -q "$pkg" && log_step "Installed $pkg"
            else
                log_step "$pkg already installed"
            fi
        done
    elif command -v dnf &>/dev/null; then
        for pkg in $packages; do
            if ! rpm -q "$pkg" &>/dev/null; then
                dnf install -y -q "$pkg" && log_step "Installed $pkg"
            else
                log_step "$pkg already installed"
            fi
        done
    else
        log_warn "Unknown package manager. Please install manually: $packages"
    fi
}

create_directories() {
    log_info "Creating directories..."
    mkdir -p "$CONFIG_DIR" "$LIB_DIR" /etc/iptables
    log_step "Directories created"
}

install_scripts() {
    log_info "Installing scripts..."

    cp "$SCRIPT_DIR/connection-monitor.sh" "$INSTALL_DIR/$MONITOR_SCRIPT"
    chmod 755 "$INSTALL_DIR/$MONITOR_SCRIPT"
    log_step "Installed $MONITOR_SCRIPT"

    cp "$SCRIPT_DIR/callback-handler.sh" "$INSTALL_DIR/$HANDLER_SCRIPT"
    chmod 755 "$INSTALL_DIR/$HANDLER_SCRIPT"
    log_step "Installed $HANDLER_SCRIPT"
}

setup_config() {
    log_info "Setting up configuration..."

    if [[ -f "$CONFIG_DIR/config.conf" ]]; then
        log_warn "Configuration file exists, preserving..."
        return
    fi

    if [[ -f "$SCRIPT_DIR/config.conf.template" ]]; then
        cp "$SCRIPT_DIR/config.conf.template" "$CONFIG_DIR/config.conf"
    else
        cat > "$CONFIG_DIR/config.conf" << 'EOF'
#===============================================================================
# Server Connection Monitor Configuration
#===============================================================================

# Telegram Bot Token (required) - Get from @BotFather
TELEGRAM_BOT_TOKEN=""

# Telegram Chat ID (required) - Get from @userinfobot
TELEGRAM_CHAT_ID=""

# Server name (auto-detected if empty)
SERVER_NAME=""

# Server IP (auto-detected if empty)
SERVER_IP=""

# SSH port (used by "Show Active Sessions" to list SSH connections)
SSH_PORT="22"

# Users to exclude (space-separated)
EXCLUDED_USERS=""

# IPs to exclude (space-separated)
EXCLUDED_IPS=""

# PAM services that never trigger alerts (prevents cron/sudo/su/systemd noise)
IGNORED_SERVICES="cron crond sudo su su-l runuser runuser-l systemd-user polkit-1 passwd chpasswd chsh chfn newgrp gdm-password gdm-launch-environment lightdm sddm xdm"

# Notify on local sessions with no remote IP (console / TTY logins); false = remote only
NOTIFY_LOCAL="true"

# Deduplication window in seconds (prevents duplicate notifications)
DEDUP_WINDOW="10"

# Enable geo-location lookup
GEO_LOOKUP="true"

# Debug mode
DEBUG="false"
EOF
    fi

    chmod 600 "$CONFIG_DIR/config.conf"
    log_step "Configuration file created at $CONFIG_DIR/config.conf"
}

configure_pam() {
    log_info "Configuring PAM..."

    local pam_line="session optional pam_exec.so seteuid $INSTALL_DIR/$MONITOR_SCRIPT notify"
    local pam_sshd="/etc/pam.d/sshd"

    # Remove any existing entries first (clean slate)
    remove_pam_entries

    if [[ -f "$pam_sshd" ]]; then
        # Backup
        cp "$pam_sshd" "$pam_sshd.backup.$(date +%Y%m%d%H%M%S)"

        # Add entry
        {
            echo ""
            echo "# Connection Monitor - Telegram notifications"
            echo "$pam_line"
        } >> "$pam_sshd"

        log_step "PAM configured for SSH monitoring"
    else
        log_warn "PAM sshd file not found at $pam_sshd"
    fi
}

remove_pam_entries() {
    local pam_files=("/etc/pam.d/sshd" "/etc/pam.d/common-session" "/etc/pam.d/login")

    for pam_file in "${pam_files[@]}"; do
        if [[ -f "$pam_file" ]] && grep -q "connection-monitor" "$pam_file" 2>/dev/null; then
            sed -i '/connection-monitor/d' "$pam_file"
            sed -i '/# Connection Monitor/d' "$pam_file"
            # Remove multiple consecutive empty lines
            sed -i '/^$/N;/^\n$/d' "$pam_file"
        fi
    done
}

setup_systemd() {
    log_info "Setting up systemd service..."

    if [[ -f "$SCRIPT_DIR/connection-monitor-handler.service" ]]; then
        cp "$SCRIPT_DIR/connection-monitor-handler.service" "$SYSTEMD_DIR/"
    else
        cat > "$SYSTEMD_DIR/connection-monitor-handler.service" << 'EOF'
[Unit]
Description=Telegram Connection Monitor Callback Handler
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/connection-monitor-handler start
ExecStop=/usr/local/bin/connection-monitor-handler stop
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=connection-monitor-handler

# Security
PrivateTmp=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
    log_step "Systemd service installed"
}

setup_logrotate() {
    log_info "Setting up log rotation..."

    cat > /etc/logrotate.d/connection-monitor << 'EOF'
/var/log/connection-monitor.log
/var/log/connection-monitor-handler.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 root root
}
EOF

    log_step "Log rotation configured"
}

clear_caches() {
    rm -rf /tmp/connection-monitor-dedup 2>/dev/null || true
    log_step "Cleared notification caches"
}

start_services() {
    log_info "Starting services..."

    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
    systemctl restart "$SERVICE_NAME"

    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_step "Callback handler service started"
    else
        log_warn "Service may have issues. Check: journalctl -u $SERVICE_NAME -f"
    fi
}

stop_services() {
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
}

#===============================================================================
# Interactive Setup
#===============================================================================

interactive_setup() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                    Telegram Bot Configuration                      ${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    # Check if already configured
    if [[ -f "$CONFIG_DIR/config.conf" ]]; then
        source "$CONFIG_DIR/config.conf"
        if [[ -n "${TELEGRAM_BOT_TOKEN:-}" ]] && [[ "$TELEGRAM_BOT_TOKEN" != "YOUR_BOT_TOKEN_HERE" ]]; then
            log_step "Telegram already configured"
            return
        fi
    fi

    # Non-interactive: credentials supplied via environment
    #   curl ... | sudo TELEGRAM_BOT_TOKEN=xxx TELEGRAM_CHAT_ID=yyy bash
    if [[ -n "$ENV_BOT_TOKEN" ]] && [[ -n "$ENV_CHAT_ID" ]]; then
        if [[ ! -f "$CONFIG_DIR/config.conf" ]]; then
            log_warn "Config file missing; cannot apply environment credentials"
            return
        fi
        sed -i "s|^TELEGRAM_BOT_TOKEN=.*|TELEGRAM_BOT_TOKEN=\"$(esc_sed "$ENV_BOT_TOKEN")\"|" "$CONFIG_DIR/config.conf"
        sed -i "s|^TELEGRAM_CHAT_ID=.*|TELEGRAM_CHAT_ID=\"$(esc_sed "$ENV_CHAT_ID")\"|" "$CONFIG_DIR/config.conf"
        log_step "Telegram credentials configured from environment"
        return
    fi

    # No way to prompt (ASSUME_YES, or piped with no controlling terminal):
    # finish the install and let the user add credentials afterwards.
    if [[ "$ASSUME_YES" == "true" ]] || { [[ ! -t 0 ]] && [[ ! -e /dev/tty ]]; }; then
        log_warn "Telegram not configured (non-interactive install)"
        log_info "Add credentials: sudo nano $CONFIG_DIR/config.conf"
        log_info "Then restart:    sudo systemctl restart $SERVICE_NAME"
        return
    fi

    cat << 'EOF'
To set up Telegram notifications, you need:

1. A Telegram Bot Token:
   - Open Telegram and search for @BotFather
   - Send /newbot and follow the instructions
   - Copy the bot token provided

2. Your Chat ID:
   - Search for @userinfobot in Telegram
   - Start the bot and it will show your Chat ID

EOF

    ask "Configure Telegram now? (y/n): " configure_now "n"

    if [[ "$configure_now" =~ ^[Yy]$ ]]; then
        ask "Enter your Telegram Bot Token: " bot_token ""
        ask "Enter your Telegram Chat ID: " chat_id ""

        if [[ -n "$bot_token" ]] && [[ -n "$chat_id" ]]; then
            sed -i "s|^TELEGRAM_BOT_TOKEN=.*|TELEGRAM_BOT_TOKEN=\"$(esc_sed "$bot_token")\"|" "$CONFIG_DIR/config.conf"
            sed -i "s|^TELEGRAM_CHAT_ID=.*|TELEGRAM_CHAT_ID=\"$(esc_sed "$chat_id")\"|" "$CONFIG_DIR/config.conf"
            log_step "Telegram credentials saved"

            echo ""
            ask "Send a test notification? (y/n): " send_test "n"
            if [[ "$send_test" =~ ^[Yy]$ ]]; then
                run_test
            fi
        else
            log_warn "Credentials not provided. Edit $CONFIG_DIR/config.conf manually."
        fi
    else
        log_info "Edit $CONFIG_DIR/config.conf to add your credentials later."
    fi
}

#===============================================================================
# Command Implementations
#===============================================================================

cmd_install() {
    print_banner
    log_info "Starting fresh installation..."
    echo ""

    check_root
    check_os
    check_source_files

    if check_installed; then
        log_warn "Existing installation detected. Use 'update' to update or 'uninstall' first."
        ask "Continue with fresh install anyway? (y/n): " continue_install "n"
        [[ "$continue_install" =~ ^[Yy]$ ]] || exit 0
    fi

    install_dependencies
    create_directories
    install_scripts
    setup_config
    configure_pam
    setup_systemd
    setup_logrotate
    clear_caches
    interactive_setup
    start_services

    print_summary
}

cmd_update() {
    print_banner
    log_info "Updating existing installation..."
    echo ""

    check_root
    check_source_files

    if ! check_installed; then
        die "No existing installation found. Use 'install' for fresh installation."
    fi

    # Stop service
    log_info "Stopping services..."
    stop_services

    # Update scripts
    install_scripts

    # Fix PAM configuration
    log_info "Fixing PAM configuration..."
    configure_pam

    # Clear caches
    clear_caches

    # Update systemd service
    setup_systemd

    # Start service
    start_services

    echo ""
    log_step "Update complete!"
    echo ""
    echo "Changes applied:"
    echo "  • Scripts updated to latest version"
    echo "  • PAM configuration fixed (removed duplicates)"
    echo "  • Notification caches cleared"
    echo "  • Service restarted"
    echo ""
    echo "Test with: ssh user@this-server"
}

cmd_fix() {
    print_banner
    log_info "Fixing duplicate notification issues..."
    echo ""

    check_root

    # Remove from common-session if present
    if [[ -f "/etc/pam.d/common-session" ]] && grep -q "connection-monitor" "/etc/pam.d/common-session" 2>/dev/null; then
        sed -i '/connection-monitor/d' "/etc/pam.d/common-session"
        sed -i '/# Connection Monitor/d' "/etc/pam.d/common-session"
        sed -i '/^$/N;/^\n$/d' "/etc/pam.d/common-session"
        log_step "Removed duplicate PAM entry from common-session"
    else
        log_info "No duplicate entry in common-session"
    fi

    # Ensure sshd PAM has seteuid flag
    if [[ -f "/etc/pam.d/sshd" ]] && grep -q "connection-monitor" "/etc/pam.d/sshd" 2>/dev/null; then
        if ! grep -q "seteuid" "/etc/pam.d/sshd" 2>/dev/null; then
            sed -i 's|pam_exec.so /usr/local/bin/connection-monitor|pam_exec.so seteuid /usr/local/bin/connection-monitor|g' "/etc/pam.d/sshd"
            log_step "Added seteuid flag to PAM config"
        fi
    fi

    # Clear dedup cache
    clear_caches

    # Update script if newer version available
    if [[ -f "$SCRIPT_DIR/connection-monitor.sh" ]] && [[ -f "$INSTALL_DIR/$MONITOR_SCRIPT" ]]; then
        if ! cmp -s "$SCRIPT_DIR/connection-monitor.sh" "$INSTALL_DIR/$MONITOR_SCRIPT"; then
            cp "$SCRIPT_DIR/connection-monitor.sh" "$INSTALL_DIR/$MONITOR_SCRIPT"
            chmod 755 "$INSTALL_DIR/$MONITOR_SCRIPT"
            log_step "Updated connection-monitor script"
        fi
    fi

    echo ""
    log_step "Fix complete!"
    echo "SSH connections should now produce only 1 notification."
    echo ""
    echo "Test with: ssh user@this-server"
}

cmd_uninstall() {
    print_banner
    log_info "Uninstalling Server Connection Monitor..."
    echo ""

    check_root

    # Stop and disable service
    stop_services

    # Remove systemd service
    rm -f "$SYSTEMD_DIR/connection-monitor-handler.service"
    systemctl daemon-reload
    log_step "Removed systemd service"

    # Remove scripts
    rm -f "$INSTALL_DIR/$MONITOR_SCRIPT"
    rm -f "$INSTALL_DIR/$HANDLER_SCRIPT"
    log_step "Removed scripts"

    # Remove PAM configuration
    remove_pam_entries
    log_step "Removed PAM configuration"

    # Remove logrotate config
    rm -f /etc/logrotate.d/connection-monitor
    log_step "Removed logrotate configuration"

    # Clear caches
    clear_caches
    rm -f /var/run/connection-monitor-handler.pid

    # Ask about config and data (default: keep, for safety in non-interactive runs)
    echo ""
    ask "Remove configuration and logs? (y/n): " remove_data "n"
    if [[ "$remove_data" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        rm -rf "$LIB_DIR"
        rm -f /var/log/connection-monitor*.log
        log_step "Configuration and logs removed"
    else
        log_info "Configuration preserved at $CONFIG_DIR"
    fi

    echo ""
    log_step "Uninstallation complete!"
}

cmd_status() {
    print_banner

    echo -e "${CYAN}Installation Status:${NC}"
    if check_installed; then
        log_step "Scripts installed"
    else
        log_error "Scripts not installed"
    fi

    if [[ -f "$CONFIG_DIR/config.conf" ]]; then
        log_step "Configuration file exists"
        source "$CONFIG_DIR/config.conf" 2>/dev/null || true
        if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ "$TELEGRAM_BOT_TOKEN" != "YOUR_BOT_TOKEN_HERE" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
            log_step "Telegram configured"
        else
            log_warn "Telegram not configured"
        fi
    else
        log_error "Configuration file missing"
    fi

    echo ""
    echo -e "${CYAN}Service Status:${NC}"
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_step "Callback handler is running"
        echo "  PID: $(systemctl show -p MainPID --value "$SERVICE_NAME")"
    else
        log_error "Callback handler is not running"
    fi

    echo ""
    echo -e "${CYAN}PAM Configuration:${NC}"
    if grep -q "connection-monitor" /etc/pam.d/sshd 2>/dev/null; then
        log_step "PAM configured for SSH"
    else
        log_warn "PAM not configured for SSH"
    fi

    if grep -q "connection-monitor" /etc/pam.d/common-session 2>/dev/null; then
        log_warn "Duplicate entry in common-session (run 'fix' to resolve)"
    fi

    echo ""
    echo -e "${CYAN}Recent Logs:${NC}"
    if [[ -f /var/log/connection-monitor.log ]]; then
        tail -5 /var/log/connection-monitor.log 2>/dev/null || echo "  (no recent entries)"
    else
        echo "  (no log file)"
    fi
}

run_test() {
    log_info "Sending test notification..."
    if "$INSTALL_DIR/$MONITOR_SCRIPT" test 2>/dev/null; then
        log_step "Test notification sent! Check your Telegram."
    else
        log_error "Test failed. Check configuration and logs."
    fi
}

cmd_test() {
    print_banner
    check_root

    if ! check_installed; then
        die "Not installed. Run 'install' first."
    fi

    run_test
}

print_summary() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    Installation Complete!                          ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Installed files:"
    echo "  • Monitor:        $INSTALL_DIR/$MONITOR_SCRIPT"
    echo "  • Handler:        $INSTALL_DIR/$HANDLER_SCRIPT"
    echo "  • Configuration:  $CONFIG_DIR/config.conf"
    echo "  • Service:        $SERVICE_NAME.service"
    echo ""
    echo "Manage:"
    echo "  • Test:       sudo $MONITOR_SCRIPT test"
    echo "  • Status:     sudo systemctl status $SERVICE_NAME"
    echo "  • Update:     curl -fsSL $GITHUB_RAW_URL/install.sh | sudo bash -s update"
    echo "  • Uninstall:  curl -fsSL $GITHUB_RAW_URL/install.sh | sudo bash -s uninstall"
    echo ""
    echo "Logs:"
    echo "  • Notifications:  tail -f /var/log/connection-monitor.log"
    echo "  • Handler:        journalctl -u $SERVICE_NAME -f"
    echo ""
}

print_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  install     Fresh installation (default)"
    echo "  update      Update existing installation"
    echo "  fix         Fix duplicate notifications"
    echo "  uninstall   Remove installation"
    echo "  test        Test Telegram notification"
    echo "  status      Show installation status"
    echo "  help        Show this help"
    echo ""
    echo "Remote (no checkout needed):"
    echo "  curl -fsSL $GITHUB_RAW_URL/install.sh | sudo bash"
    echo "  curl -fsSL $GITHUB_RAW_URL/install.sh | sudo bash -s update"
    echo ""
    echo "Non-interactive environment variables:"
    echo "  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID   Preconfigure credentials"
    echo "  ASSUME_YES=true                        Skip all prompts"
    echo ""
}

#===============================================================================
# Main
#===============================================================================

main() {
    case "${1:-install}" in
        install)    cmd_install ;;
        update)     cmd_update ;;
        fix)        cmd_fix ;;
        uninstall)  cmd_uninstall ;;
        test)       cmd_test ;;
        status)     cmd_status ;;
        help|--help|-h)
            print_banner
            print_usage
            ;;
        *)
            print_usage
            exit 1
            ;;
    esac
}

main "$@"
