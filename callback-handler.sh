#!/bin/bash
#===============================================================================
# Server Connection Monitor - Telegram Callback Handler
#
# Long-polling daemon that processes inline keyboard button presses
# Handles: Block IP, Kick User, Show Sessions
#
# License: MIT
#===============================================================================

set -o pipefail

# Configuration
readonly CONFIG_FILE="/etc/connection-monitor/config.conf"
readonly OFFSET_FILE="/var/lib/connection-monitor/last_update_id"
readonly PID_FILE="/var/run/connection-monitor-handler.pid"
readonly LOG_FILE="/var/log/connection-monitor-handler.log"

# Load configuration
if [[ -f "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
else
    echo "Error: Configuration file not found at $CONFIG_FILE" >&2
    exit 1
fi

# Defaults
SERVER_NAME="${SERVER_NAME:-$(hostname -f 2>/dev/null || hostname)}"

#===============================================================================
# Logging
#===============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

#===============================================================================
# State Management
#===============================================================================

get_last_offset() {
    if [[ -f "$OFFSET_FILE" ]]; then
        cat "$OFFSET_FILE"
    else
        echo "0"
    fi
}

save_offset() {
    local offset="$1"
    mkdir -p "$(dirname "$OFFSET_FILE")"
    echo "$offset" > "$OFFSET_FILE"
}

#===============================================================================
# Telegram API
#===============================================================================

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null
}

answer_callback_query() {
    local callback_query_id="$1"
    local text="$2"
    local show_alert="${3:-false}"

    timeout 5 curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery" \
        -H "Content-Type: application/json" \
        -d "{
            \"callback_query_id\": \"$callback_query_id\",
            \"text\": \"$text\",
            \"show_alert\": $show_alert
        }" >/dev/null 2>&1 || log "WARN" "Failed to answer callback query"
}

send_message() {
    local text="$1"
    local escaped_text
    escaped_text=$(echo "$text" | json_escape)

    timeout 10 curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{
            \"chat_id\": \"${TELEGRAM_CHAT_ID}\",
            \"text\": ${escaped_text},
            \"parse_mode\": \"HTML\"
        }" >/dev/null 2>&1 || log "WARN" "Failed to send message"
}

get_updates() {
    local offset="$1"
    local poll_timeout="${2:-10}"

    timeout 15 curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates" \
        -H "Content-Type: application/json" \
        -d "{
            \"offset\": $offset,
            \"timeout\": $poll_timeout,
            \"allowed_updates\": [\"callback_query\"]
        }" 2>/dev/null || echo '{"ok":false}'
}

#===============================================================================
# Action Handlers
#===============================================================================

block_ip() {
    local ip="$1"

    log "INFO" "Blocking IP: $ip"

    # Validate IP format (IPv4 or IPv6)
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
       ! [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
        log "ERROR" "Invalid IP format: $ip"
        return 2
    fi

    # Refuse to block local IPs
    if [[ "$ip" == "Local/Unknown" ]] || [[ "$ip" =~ ^127\. ]]; then
        log "WARN" "Refusing to block local IP: $ip"
        return 2
    fi

    # Check if already blocked
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        log "INFO" "IP already blocked: $ip"
        return 3
    fi

    # Block the IP
    if iptables -A INPUT -s "$ip" -j DROP 2>&1; then
        log "INFO" "Successfully blocked IP: $ip"

        # Save iptables rules
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save 2>/dev/null || true
        elif command -v iptables-save &>/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi

        # Add to hosts.deny
        if ! grep -q "ALL: $ip" /etc/hosts.deny 2>/dev/null; then
            echo "ALL: $ip # Blocked by connection-monitor $(date '+%Y-%m-%d %H:%M:%S')" >> /etc/hosts.deny
        fi

        # Add to fail2ban if available
        if command -v fail2ban-client &>/dev/null; then
            fail2ban-client set sshd banip "$ip" 2>/dev/null || true
        fi

        return 0
    else
        log "ERROR" "Failed to block IP: $ip"
        return 4
    fi
}

kick_user() {
    local user="$1"
    local ip="$2"
    local session_id="$3"

    log "INFO" "Kick request: user=$user ip=$ip session=$session_id"

    local kicked=0

    # Method 1: Terminate by session ID
    if [[ -n "$session_id" ]] && [[ "$session_id" != "$$" ]]; then
        if loginctl terminate-session "$session_id" 2>/dev/null; then
            log "INFO" "Terminated session: $session_id"
            ((kicked++))
        fi
    fi

    # Method 2: Kill SSH sessions from specific IP
    if [[ -n "$ip" ]] && [[ "$ip" != "Local/Unknown" ]]; then
        local pids
        pids=$(ss -tnp 2>/dev/null | grep "$ip" | grep sshd | grep -oP 'pid=\K[0-9]+' | sort -u)
        for pid in $pids; do
            local proc_user
            proc_user=$(ps -o user= -p "$pid" 2>/dev/null)
            if [[ "$proc_user" == "$user" ]] || [[ "$proc_user" == "root" ]]; then
                if kill -9 "$pid" 2>/dev/null; then
                    log "INFO" "Killed process $pid"
                    ((kicked++))
                fi
            fi
        done
    fi

    # Method 3: Kill all user's PTY sessions
    local user_ttys
    user_ttys=$(who 2>/dev/null | grep "^$user " | awk '{print $2}')
    for tty in $user_ttys; do
        local tty_pid
        tty_pid=$(ps -t "$tty" -o pid= 2>/dev/null | head -1 | tr -d ' ')
        if [[ -n "$tty_pid" ]]; then
            if kill -9 "$tty_pid" 2>/dev/null; then
                log "INFO" "Killed TTY process $tty_pid on $tty"
                ((kicked++))
            fi
        fi
    done

    # Method 4: pkill fallback
    if pkill -9 -u "$user" sshd 2>/dev/null; then
        log "INFO" "Killed sshd processes for user: $user"
        ((kicked++))
    fi

    if [[ $kicked -gt 0 ]]; then
        log "INFO" "Kicked user $user ($kicked processes/sessions)"
        return 0
    else
        log "WARN" "No active sessions found for user: $user"
        return 1
    fi
}

get_active_sessions() {
    local sessions=""
    local count=0

    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            local sess_user sess_tty sess_from
            sess_user=$(echo "$line" | awk '{print $1}')
            sess_tty=$(echo "$line" | awk '{print $2}')
            sess_from=$(echo "$line" | awk '{print $5}' | tr -d '()')
            sessions+="👤 <code>$sess_user</code> | 📺 $sess_tty | 📡 ${sess_from:-local}
"
            ((count++))
        fi
    done < <(who 2>/dev/null)

    if [[ $count -eq 0 ]]; then
        echo "📋 <b>Active Sessions on $SERVER_NAME</b>

✨ No active sessions

🕐 Checked: $(date '+%Y-%m-%d %H:%M:%S')"
    else
        echo "📋 <b>Active Sessions on $SERVER_NAME</b>

$sessions
🕐 Updated: $(date '+%Y-%m-%d %H:%M:%S')"
    fi
}

#===============================================================================
# Callback Processing
#===============================================================================

process_callback() {
    local callback_query_id="$1"
    local data="$2"
    local chat_id="$3"
    local from_id="$4"

    log "INFO" "Processing callback: $data from user $from_id"

    # Verify authorized chat
    if [[ "$chat_id" != "$TELEGRAM_CHAT_ID" ]]; then
        log "WARN" "Unauthorized callback from chat: $chat_id"
        answer_callback_query "$callback_query_id" "Unauthorized" true
        return
    fi

    # Parse callback data
    local action
    action=$(echo "$data" | cut -d: -f1)

    case "$action" in
        block)
            local ip target_server
            ip=$(echo "$data" | cut -d: -f2)
            target_server=$(echo "$data" | cut -d: -f3)

            # Only process if for this server
            if [[ "$target_server" != "$SERVER_NAME" ]]; then
                log "INFO" "Block request not for this server (target: $target_server)"
                return 1
            fi

            local exit_code=0
            block_ip "$ip" || exit_code=$?

            case $exit_code in
                0)
                    answer_callback_query "$callback_query_id" "IP $ip blocked on $SERVER_NAME" true
                    send_message "🚫 <b>IP Blocked</b>

🖥️ Server: <code>$SERVER_NAME</code>
📡 IP: <code>$ip</code>
🕐 Time: $(date '+%Y-%m-%d %H:%M:%S')
👤 By: User $from_id"
                    ;;
                2)
                    answer_callback_query "$callback_query_id" "Invalid IP format" true
                    ;;
                3)
                    answer_callback_query "$callback_query_id" "IP already blocked" true
                    ;;
                *)
                    answer_callback_query "$callback_query_id" "Failed to block IP (error: $exit_code)" true
                    ;;
            esac
            ;;

        kick)
            local user ip session_id
            user=$(echo "$data" | cut -d: -f2)
            ip=$(echo "$data" | cut -d: -f3)
            session_id=$(echo "$data" | cut -d: -f4)

            if kick_user "$user" "$ip" "$session_id"; then
                answer_callback_query "$callback_query_id" "User $user kicked from $SERVER_NAME" true
                send_message "👢 <b>User Kicked</b>

🖥️ Server: <code>$SERVER_NAME</code>
👤 User: <code>$user</code>
📡 IP: <code>$ip</code>
🕐 Time: $(date '+%Y-%m-%d %H:%M:%S')"
            else
                answer_callback_query "$callback_query_id" "No active sessions for $user" false
            fi
            ;;

        sessions)
            local target_server
            target_server=$(echo "$data" | cut -d: -f2)

            if [[ "$target_server" != "$SERVER_NAME" ]]; then
                log "INFO" "Sessions request not for this server (target: $target_server)"
                return 1
            fi

            local session_count
            session_count=$(who 2>/dev/null | wc -l)
            answer_callback_query "$callback_query_id" "Found $session_count active session(s)" false

            local sessions_msg
            sessions_msg=$(get_active_sessions)
            send_message "$sessions_msg"
            ;;

        *)
            log "WARN" "Unknown callback action: $action"
            answer_callback_query "$callback_query_id" "Unknown action: $action" true
            ;;
    esac
}

#===============================================================================
# Daemon Control
#===============================================================================

cleanup() {
    log "INFO" "Shutting down callback handler..."
    rm -f "$PID_FILE"
    exit 0
}

trap cleanup SIGTERM SIGINT

start_daemon() {
    # Check if already running
    if [[ -f "$PID_FILE" ]]; then
        local old_pid
        old_pid=$(cat "$PID_FILE")
        if kill -0 "$old_pid" 2>/dev/null; then
            echo "Daemon already running with PID $old_pid"
            exit 1
        fi
    fi

    # Create directories
    mkdir -p "$(dirname "$PID_FILE")"
    mkdir -p "$(dirname "$OFFSET_FILE")"
    mkdir -p "$(dirname "$LOG_FILE")"

    # Save PID
    echo $$ > "$PID_FILE"

    log "INFO" "Starting callback handler (PID: $$)"
    echo "Callback handler started with PID $$"

    local offset
    offset=$(get_last_offset)

    # Main polling loop
    while true; do
        local response
        response=$(get_updates "$offset" 10)

        if [[ -z "$response" ]] || [[ "$response" == '{"ok":false}' ]]; then
            log "WARN" "Empty or failed response from Telegram API"
            sleep 5
            continue
        fi

        if echo "$response" | grep -q '"ok":false'; then
            log "ERROR" "Telegram API error: $response"
            sleep 10
            continue
        fi

        # Parse updates using Python
        local updates
        updates=$(echo "$response" | python3 -c "
import json
import sys

try:
    data = json.load(sys.stdin)
    if not data.get('ok', False):
        sys.exit(0)
    for update in data.get('result', []):
        update_id = update.get('update_id', 0)
        cb = update.get('callback_query')
        if cb:
            cb_id = cb.get('id', '')
            cb_data = cb.get('data', '')
            msg = cb.get('message', {})
            chat_id = str(msg.get('chat', {}).get('id', ''))
            from_id = str(cb.get('from', {}).get('id', ''))
            print(f'{update_id}|{cb_id}|{cb_data}|{chat_id}|{from_id}')
except Exception as e:
    sys.stderr.write(f'Parse error: {e}\n')
    sys.exit(0)
" 2>/dev/null)

        if [[ -z "$updates" ]]; then
            sleep 1
            continue
        fi

        while IFS='|' read -r update_id cb_id cb_data chat_id from_id; do
            if [[ -n "$update_id" ]] && [[ "$update_id" =~ ^[0-9]+$ ]] && [[ "$update_id" -gt "$offset" ]]; then
                offset=$((update_id + 1))
                save_offset "$offset"

                if [[ -n "$cb_id" ]] && [[ -n "$cb_data" ]]; then
                    log "DEBUG" "Processing: update=$update_id cb=$cb_data chat=$chat_id"
                    process_callback "$cb_id" "$cb_data" "$chat_id" "$from_id" &
                    wait $!
                fi
            fi
        done <<< "$updates"

        sleep 1
    done
}

stop_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "Daemon stopped (PID: $pid)"
            rm -f "$PID_FILE"
        else
            echo "Daemon not running"
            rm -f "$PID_FILE"
        fi
    else
        echo "PID file not found"
    fi
}

status_daemon() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            echo "Daemon is running (PID: $pid)"
            return 0
        else
            echo "Daemon is not running (stale PID file)"
            return 1
        fi
    else
        echo "Daemon is not running"
        return 1
    fi
}

#===============================================================================
# Entry Point
#===============================================================================

case "${1:-start}" in
    start)   start_daemon ;;
    stop)    stop_daemon ;;
    restart)
        stop_daemon
        sleep 2
        start_daemon
        ;;
    status)  status_daemon ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
