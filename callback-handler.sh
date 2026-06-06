#!/bin/bash
#===============================================================================
# Server Connection Monitor - Telegram Callback Handler
#
# Long-polling daemon that processes inline keyboard button presses
# Handles: Block IP, Unblock IP, Kick User, Show Sessions
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
SSH_PORT="${SSH_PORT:-22}"

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

# HTML-escape a string for Telegram parse_mode=HTML; result is stored in the
# global _ESC. Pure bash (no subshell). '&' is replaced first so the '&' it
# introduces for '<'/'>' is not re-escaped. Note: bash 5.2+ enables
# patsub_replacement by default, which expands an unquoted '&' in a
# ${var//pat/repl} replacement to the matched text — so we emit it as '\&'
# there (on bash <5.2 the option is absent and a plain '&' is already literal).
html_escape() {
    local s="$1" amp='&'
    shopt -q patsub_replacement 2>/dev/null && amp='\&'
    s="${s//&/${amp}amp;}"
    s="${s//</${amp}lt;}"
    s="${s//>/${amp}gt;}"
    _ESC="$s"
}

answer_callback_query() {
    local callback_query_id="$1"
    local text="$2"
    local show_alert="${3:-false}"

    timeout 10 curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/answerCallbackQuery" \
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

send_message_with_keyboard() {
    local text="$1"
    local keyboard="$2"
    local escaped_text
    escaped_text=$(echo "$text" | json_escape)

    timeout 10 curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{
            \"chat_id\": \"${TELEGRAM_CHAT_ID}\",
            \"text\": ${escaped_text},
            \"parse_mode\": \"HTML\",
            \"reply_markup\": $keyboard
        }" >/dev/null 2>&1 || log "WARN" "Failed to send message with keyboard"
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

warmup_api() {
    # Pre-establish HTTPS connection to Telegram API
    # This ensures first callback response is fast (DNS, TLS already done)
    log "INFO" "Warming up Telegram API connection..."
    timeout 10 curl -sS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe" \
        -H "Content-Type: application/json" >/dev/null 2>&1 && \
        log "INFO" "API warmup successful" || \
        log "WARN" "API warmup failed (will retry on first request)"
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

unblock_ip() {
    local ip="$1"

    log "INFO" "Unblocking IP: $ip"

    # Validate IP format (IPv4 or IPv6)
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && \
       ! [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
        log "ERROR" "Invalid IP format: $ip"
        return 2
    fi

    local unblocked=0

    # Remove from iptables
    if iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
        if iptables -D INPUT -s "$ip" -j DROP 2>&1; then
            log "INFO" "Removed iptables rule for IP: $ip"
            ((unblocked++))
        fi
    fi

    # Save iptables rules
    if [[ $unblocked -gt 0 ]]; then
        if command -v netfilter-persistent &>/dev/null; then
            netfilter-persistent save 2>/dev/null || true
        elif command -v iptables-save &>/dev/null; then
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi

    # Remove from hosts.deny
    if grep -q "ALL: $ip" /etc/hosts.deny 2>/dev/null; then
        sed -i "/ALL: $ip/d" /etc/hosts.deny
        log "INFO" "Removed from hosts.deny: $ip"
        ((unblocked++))
    fi

    # Remove from fail2ban if available
    if command -v fail2ban-client &>/dev/null; then
        fail2ban-client set sshd unbanip "$ip" 2>/dev/null || true
    fi

    if [[ $unblocked -gt 0 ]]; then
        log "INFO" "Successfully unblocked IP: $ip"
        return 0
    else
        log "WARN" "IP was not blocked: $ip"
        return 3
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
        pids=$(ss -tnp 2>/dev/null | grep -F "$ip" | grep sshd | grep -oP 'pid=\K[0-9]+' | sort -u)
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
    local ssh_port="${SSH_PORT:-22}"
    local output=""
    local total_count=0
    local _ESC=""

    #---------------------------------------------------------------------------
    # Section 1: Interactive sessions (single 'w' call, parsed in one pass)
    #---------------------------------------------------------------------------
    output+="<b>👥 Interactive Sessions:</b>
"
    local interactive_count=0

    # 'w -h' columns: USER TTY FROM LOGIN@ IDLE JCPU PCPU WHAT
    # read assigns the remainder of the line (the full command) to 'what'.
    local user tty from login idle jcpu pcpu what
    while read -r user tty from login idle jcpu pcpu what; do
        [[ -z "$user" ]] && continue

        # Determine session type and icon
        local type_icon type_name
        if [[ "$tty" == pts* ]]; then
            if [[ "$from" == :* ]]; then
                type_icon="🖼️"; type_name="X11"
            elif [[ -n "$from" && "$from" != "-" ]]; then
                type_icon="🔑"; type_name="SSH"
            else
                type_icon="📺"; type_name="PTY"
            fi
        elif [[ "$tty" == tty[0-9]* ]]; then
            type_icon="🖥️"; type_name="Console"
        else
            type_icon="📟"; type_name="Other"
        fi

        html_escape "$user"
        output+="$type_icon <code>$_ESC</code> [$type_name]
"
        output+="   ├ TTY: $tty"
        if [[ -n "$from" && "$from" != "-" ]]; then
            html_escape "$from"
            output+=" │ From: <code>$_ESC</code>"
        fi
        output+="
"
        [[ -n "$idle" && "$idle" != "0.00s" && "$idle" != "." ]] && \
            output+="   ├ Idle: $idle
"
        html_escape "${what:0:40}"
        output+="   └ Cmd: <code>$_ESC</code>
"

        ((interactive_count++))
        ((total_count++))
    done < <(w -h 2>/dev/null)

    [[ $interactive_count -eq 0 ]] && output+="   ✨ None
"

    #---------------------------------------------------------------------------
    # Section 2: Established SSH network connections (deduped by peer IP)
    #---------------------------------------------------------------------------
    output+="
<b>🔌 SSH Connections (port ${ssh_port}):</b>
"
    local ssh_count=0
    declare -A seen_ips=()

    # 'ss -tnpH' columns: State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port Process
    local state recvq sendq local_addr peer process
    while read -r state recvq sendq local_addr peer process; do
        [[ "$state" == ESTAB ]] || continue

        # Split "addr:port"; IPv6 peers are formatted as "[addr]:port"
        local peer_ip="${peer%:*}" peer_port="${peer##*:}"
        peer_ip="${peer_ip#[}"; peer_ip="${peer_ip%]}"

        [[ -z "$peer_ip" || "$peer_ip" == 127.* || "$peer_ip" == "::1" ]] && continue
        [[ -n "${seen_ips[$peer_ip]:-}" ]] && continue
        seen_ips[$peer_ip]=1

        # Process name (only present when running as root): users:(("sshd",...))
        local proc_info=""
        [[ "$process" =~ \"([^\"]+)\" ]] && proc_info="${BASH_REMATCH[1]}"

        output+="   📡 <code>$peer_ip</code>:$peer_port"
        if [[ -n "$proc_info" ]]; then
            html_escape "$proc_info"
            output+=" ($_ESC)"
        fi
        output+="
"

        ((ssh_count++))
        ((total_count++))
    done < <(ss -tnpH "sport = :$ssh_port" 2>/dev/null)

    [[ $ssh_count -eq 0 ]] && output+="   ✨ None
"

    #---------------------------------------------------------------------------
    # Section 3: systemd login sessions (loginctl, enriched per session)
    #
    # The first column of 'list-sessions' is always the session id (stable
    # across systemd versions); everything else is read from 'show-session'
    # as Key=Value pairs, so we never depend on the table's column layout.
    #---------------------------------------------------------------------------
    if command -v loginctl &>/dev/null; then
        output+="
<b>🎫 Login Sessions:</b>
"
        local session_count=0

        local sid
        while read -r sid _; do
            # systemd session IDs are alphanumeric (sd-login spec), not just digits
            [[ "$sid" =~ ^[a-zA-Z0-9]+$ ]] || continue

            local s_name s_type s_class s_state s_remote s_remhost s_service s_tty
            s_name=""; s_type=""; s_class=""; s_state=""
            s_remote=""; s_remhost=""; s_service=""; s_tty=""
            local key val
            while IFS='=' read -r key val; do
                case "$key" in
                    Name)       s_name="$val" ;;
                    Type)       s_type="$val" ;;
                    Class)      s_class="$val" ;;
                    State)      s_state="$val" ;;
                    Remote)     s_remote="$val" ;;
                    RemoteHost) s_remhost="$val" ;;
                    Service)    s_service="$val" ;;
                    TTY)        s_tty="$val" ;;
                esac
            done < <(loginctl show-session "$sid" \
                        -p Name -p Type -p Class -p State \
                        -p Remote -p RemoteHost -p Service -p TTY 2>/dev/null)

            # Pick an icon from remote flag / class / type
            local s_icon
            if [[ "$s_remote" == "yes" || -n "$s_remhost" ]]; then
                s_icon="🔑"
            elif [[ "$s_class" == greeter ]]; then
                s_icon="🪟"
            elif [[ "$s_type" == x11 || "$s_type" == wayland || "$s_type" == mir ]]; then
                s_icon="🖼️"
            elif [[ "$s_type" == tty ]]; then
                s_icon="🖥️"
            else
                s_icon="📟"
            fi

            html_escape "${s_name:-?}"
            output+="$s_icon #$sid <code>$_ESC</code>"
            [[ -n "$s_class" ]] && output+=" [$s_class]"
            output+="
"

            local detail=""
            if [[ -n "$s_remhost" ]]; then
                html_escape "$s_remhost"
                detail="From: <code>$_ESC</code>"
            fi
            if [[ -n "$s_tty" && "$s_tty" != "-" ]]; then
                [[ -n "$detail" ]] && detail+=" │ "
                detail+="TTY: $s_tty"
            fi
            if [[ -n "$s_service" ]]; then
                [[ -n "$detail" ]] && detail+=" │ "
                html_escape "$s_service"
                detail+="via: $_ESC"
            fi
            [[ -n "$detail" ]] && output+="   ├ $detail
"
            output+="   └ State: ${s_state:-unknown}
"

            ((session_count++))
        done < <(loginctl list-sessions --no-legend 2>/dev/null)

        [[ $session_count -eq 0 ]] && output+="   ✨ None
"
    fi

    # Footer with summary
    output+="
━━━━━━━━━━━━━━━━━━━━━━
📊 Total: $total_count active connection(s)
🕐 $(date '+%Y-%m-%d %H:%M:%S')"

    echo "📋 <b>Active Sessions on $SERVER_NAME</b>

$output"
}

#===============================================================================
# Callback Processing
#===============================================================================

process_callback() {
    local callback_query_id="$1"
    local data="$2"
    local chat_id="$3"
    local from_id="$4"
    local _ESC=""

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

            # Only process if for this server (skip if target specified and doesn't match)
            if [[ -n "$target_server" ]] && [[ "$target_server" != "$SERVER_NAME" ]]; then
                log "INFO" "Block request not for this server (target: $target_server)"
                # Don't answer - let the correct server handle it
                return 0
            fi

            local exit_code=0
            block_ip "$ip" || exit_code=$?

            case $exit_code in
                0)
                    answer_callback_query "$callback_query_id" "IP $ip blocked on $SERVER_NAME" true
                    # Raw $ip in callback_data; HTML-escaped copy for the message
                    local unblock_keyboard="{\"inline_keyboard\":[[{\"text\":\"✅ Unblock IP\",\"callback_data\":\"unblock:$ip:$SERVER_NAME\"}]]}"
                    html_escape "$ip"
                    send_message_with_keyboard "🚫 <b>IP Blocked</b>

🖥️ Server: <code>$SERVER_NAME</code>
📡 IP: <code>$_ESC</code>
🕐 Time: $(date '+%Y-%m-%d %H:%M:%S')
👤 By: User $from_id" "$unblock_keyboard"
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

        unblock)
            local ip target_server
            ip=$(echo "$data" | cut -d: -f2)
            target_server=$(echo "$data" | cut -d: -f3)

            # Only process if for this server (skip if target specified and doesn't match)
            if [[ -n "$target_server" ]] && [[ "$target_server" != "$SERVER_NAME" ]]; then
                log "INFO" "Unblock request not for this server (target: $target_server)"
                # Don't answer - let the correct server handle it
                return 0
            fi

            local exit_code=0
            unblock_ip "$ip" || exit_code=$?

            case $exit_code in
                0)
                    answer_callback_query "$callback_query_id" "IP $ip unblocked on $SERVER_NAME" true
                    html_escape "$ip"
                    send_message "✅ <b>IP Unblocked</b>

🖥️ Server: <code>$SERVER_NAME</code>
📡 IP: <code>$_ESC</code>
🕐 Time: $(date '+%Y-%m-%d %H:%M:%S')
👤 By: User $from_id"
                    ;;
                2)
                    answer_callback_query "$callback_query_id" "Invalid IP format" true
                    ;;
                3)
                    answer_callback_query "$callback_query_id" "IP was not blocked" true
                    ;;
                *)
                    answer_callback_query "$callback_query_id" "Failed to unblock IP (error: $exit_code)" true
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
                local user_disp; html_escape "$user"; user_disp="$_ESC"
                html_escape "$ip"
                send_message "👢 <b>User Kicked</b>

🖥️ Server: <code>$SERVER_NAME</code>
👤 User: <code>$user_disp</code>
📡 IP: <code>$_ESC</code>
🕐 Time: $(date '+%Y-%m-%d %H:%M:%S')"
            else
                answer_callback_query "$callback_query_id" "No active sessions for $user" false
            fi
            ;;

        sessions)
            local target_server
            target_server=$(echo "$data" | cut -d: -f2)

            # Only process if for this server (skip if target specified and doesn't match)
            if [[ -n "$target_server" ]] && [[ "$target_server" != "$SERVER_NAME" ]]; then
                log "INFO" "Sessions request not for this server (target: $target_server)"
                # Don't answer - let the correct server handle it
                return 0
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

    # Warmup API connection (pre-establish HTTPS for faster first response)
    warmup_api

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
            if [[ -n "$update_id" ]] && [[ "$update_id" =~ ^[0-9]+$ ]] && [[ "$update_id" -ge "$offset" ]]; then
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
