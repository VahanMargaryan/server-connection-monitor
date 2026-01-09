#!/bin/bash
#===============================================================================
# Server Connection Monitor - Notification Script
#
# Monitors SSH, TTY, rsync, and other connections and sends Telegram alerts
# with inline keyboard buttons to block IP or kick user.
#
# Triggered via PAM session hooks.
#
# License: MIT
#===============================================================================

set -o pipefail

# Configuration
readonly CONFIG_FILE="/etc/connection-monitor/config.conf"
readonly LOG_FILE="/var/log/connection-monitor.log"
readonly DEDUP_DIR="/tmp/connection-monitor-dedup"

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
else
    echo "Error: Configuration file not found at $CONFIG_FILE" >&2
    exit 1
fi

# Validate required configuration
if [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]] || [[ -z "${TELEGRAM_CHAT_ID:-}" ]]; then
    echo "Error: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set" >&2
    exit 1
fi

# Defaults
SERVER_NAME="${SERVER_NAME:-$(hostname -f 2>/dev/null || hostname)}"
SERVER_IP="${SERVER_IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
DEBUG="${DEBUG:-false}"
DEDUP_WINDOW="${DEDUP_WINDOW:-10}"
GEO_LOOKUP="${GEO_LOOKUP:-true}"

#===============================================================================
# Logging
#===============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    [[ "$DEBUG" == "true" ]] && echo "[$timestamp] [$level] $message" >&2
}

#===============================================================================
# Deduplication
#===============================================================================

is_duplicate() {
    local user="$1"
    local ip="$2"
    local hash
    hash=$(echo -n "${user}:${ip}" | md5sum | cut -d' ' -f1)
    local dedup_file="${DEDUP_DIR}/${hash}"

    mkdir -p "$DEDUP_DIR" 2>/dev/null
    chmod 1777 "$DEDUP_DIR" 2>/dev/null || true

    if [[ -f "$dedup_file" ]]; then
        local file_age
        file_age=$(($(date +%s) - $(stat -c %Y "$dedup_file" 2>/dev/null || echo 0)))
        if [[ $file_age -lt $DEDUP_WINDOW ]]; then
            log "DEBUG" "Duplicate suppressed for $user from $ip (age: ${file_age}s)"
            return 0
        fi
    fi

    touch "$dedup_file"
    # Cleanup old files
    find "$DEDUP_DIR" -type f -mmin +1 -delete 2>/dev/null || true

    return 1
}

#===============================================================================
# Connection Detection
#===============================================================================

get_connection_type() {
    local user="$1"
    local tty="$2"
    local connection_type="Unknown"

    if [[ -n "${PAM_SERVICE:-}" ]]; then
        case "$PAM_SERVICE" in
            sshd)
                if pgrep -u "$user" rsync >/dev/null 2>&1; then
                    connection_type="rsync over SSH"
                elif pgrep -u "$user" scp >/dev/null 2>&1; then
                    connection_type="SCP"
                elif pgrep -u "$user" sftp-server >/dev/null 2>&1; then
                    connection_type="SFTP"
                elif [[ -z "$tty" ]] || [[ "$tty" == "none" ]] || [[ "$tty" == "?" ]]; then
                    connection_type="SSH Tunnel/Port Forward"
                else
                    connection_type="SSH"
                fi
                ;;
            login)
                connection_type="Local Console Login"
                ;;
            su|su-l)
                connection_type="su (Switch User)"
                ;;
            sudo)
                connection_type="sudo"
                ;;
            *)
                connection_type="$PAM_SERVICE"
                ;;
        esac
    fi

    echo "$connection_type"
}

get_client_ip() {
    local ip=""

    # Try PAM environment first
    if [[ -n "${PAM_RHOST:-}" ]]; then
        ip="$PAM_RHOST"
    elif [[ -n "${SSH_CLIENT:-}" ]]; then
        ip=$(echo "$SSH_CLIENT" | awk '{print $1}')
    elif [[ -n "${SSH_CONNECTION:-}" ]]; then
        ip=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    elif [[ -n "${PAM_USER:-}" ]]; then
        ip=$(who 2>/dev/null | grep "^${PAM_USER} " | awk '{print $5}' | tr -d '()' | head -1)
    fi

    # Fallback to ss if still empty or localhost
    if [[ -z "$ip" ]] || [[ "$ip" == "127.0.0.1" ]] || [[ "$ip" == "::1" ]]; then
        ip=$(ss -tnp 2>/dev/null | grep sshd | awk '{print $5}' | cut -d: -f1 | grep -v "127.0.0.1" | head -1)
    fi

    echo "${ip:-Local/Unknown}"
}

get_geo_info() {
    local ip="$1"

    # Skip for disabled or private IPs
    if [[ "$GEO_LOOKUP" != "true" ]]; then
        echo "Geo lookup disabled"
        return
    fi

    if [[ "$ip" == "Local/Unknown" ]] || \
       [[ "$ip" =~ ^10\. ]] || \
       [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] || \
       [[ "$ip" =~ ^192\.168\. ]] || \
       [[ "$ip" =~ ^127\. ]] || \
       [[ "$ip" =~ ^::1$ ]] || \
       [[ "$ip" =~ ^fd ]] || \
       [[ "$ip" =~ ^fe80 ]]; then
        echo "Private/Local Network"
        return
    fi

    # Get geo info with timeout (using HTTPS)
    local geo_info
    geo_info=$(timeout 3 curl -sS "https://ip-api.com/line/$ip?fields=country,city,isp" 2>/dev/null | tr '\n' ', ' | sed 's/,$//')

    echo "${geo_info:-Unknown Location}"
}

#===============================================================================
# Telegram API
#===============================================================================

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null
}

send_telegram_message() {
    local message="$1"
    local inline_keyboard="$2"

    local url="https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage"
    local escaped_message
    escaped_message=$(echo "$message" | json_escape)

    local payload
    payload=$(cat <<EOF
{
    "chat_id": "${TELEGRAM_CHAT_ID}",
    "text": ${escaped_message},
    "parse_mode": "HTML",
    "reply_markup": ${inline_keyboard}
}
EOF
)

    local response
    response=$(curl -sS -X POST "$url" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>&1)

    if echo "$response" | grep -q '"ok":true'; then
        log "INFO" "Telegram notification sent successfully"
        return 0
    else
        log "ERROR" "Failed to send Telegram notification: $response"
        return 1
    fi
}

create_inline_keyboard() {
    local ip="$1"
    local user="$2"
    local session_id="$3"

    cat <<EOF
{
    "inline_keyboard": [
        [
            {"text": "🚫 Block IP", "callback_data": "block:${ip}:${SERVER_NAME}"},
            {"text": "👢 Kick User", "callback_data": "kick:${user}:${ip}:${session_id}"}
        ],
        [
            {"text": "📋 Show Active Sessions", "callback_data": "sessions:${SERVER_NAME}"}
        ]
    ]
}
EOF
}

#===============================================================================
# Main Notification
#===============================================================================

send_connection_alert() {
    local user="${PAM_USER:-$USER}"
    local tty="${PAM_TTY:-}"
    tty="${tty#/dev/}"  # Remove /dev/ prefix if present
    local session_id="${XDG_SESSION_ID:-$$}"

    # Get connection details
    local client_ip
    client_ip=$(get_client_ip)

    local connection_type
    connection_type=$(get_connection_type "$user" "$tty")

    # Check for duplicate
    if is_duplicate "$user" "$client_ip"; then
        return 0
    fi

    log "INFO" "Connection detected: User=$user, IP=$client_ip, Type=$connection_type"

    # Check exclusions
    if [[ -n "${EXCLUDED_USERS:-}" ]]; then
        for excluded in $EXCLUDED_USERS; do
            if [[ "$user" == "$excluded" ]]; then
                log "INFO" "Skipping excluded user: $user"
                return 0
            fi
        done
    fi

    if [[ -n "${EXCLUDED_IPS:-}" ]]; then
        for excluded in $EXCLUDED_IPS; do
            if [[ "$client_ip" == "$excluded" ]]; then
                log "INFO" "Skipping excluded IP: $client_ip"
                return 0
            fi
        done
    fi

    # Get geo info
    local geo_info
    geo_info=$(get_geo_info "$client_ip")

    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')

    # Determine emoji
    local emoji="🔐"
    case "$connection_type" in
        *SSH*)          emoji="🔑" ;;
        *rsync*)        emoji="📦" ;;
        *SCP*|*SFTP*)   emoji="📁" ;;
        *Tunnel*|*Forward*) emoji="🚇" ;;
        *Local*|*Console*)  emoji="🖥️" ;;
        *sudo*)         emoji="⚡" ;;
        *su*)           emoji="👤" ;;
    esac

    # Build message
    local message="${emoji} <b>New Connection Alert</b>

🖥️ <b>Server:</b> <code>${SERVER_NAME}</code>
🌐 <b>Server IP:</b> <code>${SERVER_IP}</code>

👤 <b>User:</b> <code>${user}</code>
📡 <b>Client IP:</b> <code>${client_ip}</code>
📍 <b>Location:</b> ${geo_info}
🔌 <b>Type:</b> ${connection_type}
📺 <b>TTY:</b> ${tty:-N/A}
🕐 <b>Time:</b> ${timestamp}
🔢 <b>Session:</b> ${session_id}"

    # Create keyboard and send
    local keyboard
    keyboard=$(create_inline_keyboard "$client_ip" "$user" "$session_id")

    send_telegram_message "$message" "$keyboard"
}

#===============================================================================
# Entry Point
#===============================================================================

case "${1:-notify}" in
    notify)
        # Only trigger on session open
        if [[ "${PAM_TYPE:-}" == "open_session" ]] || [[ -z "${PAM_TYPE:-}" ]]; then
            send_connection_alert
        fi
        ;;
    test)
        echo "Testing Telegram notification..."
        # Set test values
        PAM_USER="${USER}"
        PAM_RHOST="203.0.113.42"
        PAM_SERVICE="sshd"
        PAM_TYPE="open_session"
        PAM_TTY="pts/0"
        # Temporarily disable dedup for test
        DEDUP_WINDOW=0
        if send_connection_alert; then
            echo "Test complete. Check your Telegram."
        else
            echo "Test failed. Check logs at $LOG_FILE"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 [notify|test]"
        exit 1
        ;;
esac

exit 0
