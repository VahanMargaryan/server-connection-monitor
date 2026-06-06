#!/usr/bin/env bash
#===============================================================================
# Server Connection Monitor - Test Suite
#
# Self-contained unit/integration tests. No root, no network, no extra tools
# required (uses python3, which the project already depends on). System commands
# (w, ss, loginctl, curl, wget, ...) are stubbed, so results are deterministic.
#
# Usage:  ./tests/run-tests.sh            # run everything
# Exit code is non-zero if any test fails (CI friendly).
#===============================================================================

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CB="$ROOT/callback-handler.sh"
CM="$ROOT/connection-monitor.sh"
INSTALL="$ROOT/install.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
FAILED=()

GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'

section() { printf '\n%s== %s ==%s\n' "$CYAN" "$1" "$NC"; }
ok()      { printf '  %s✓%s %s\n' "$GREEN" "$NC" "$1"; PASS=$((PASS+1)); }
bad()     { printf '  %s✗%s %s\n' "$RED" "$NC" "$1"; FAIL=$((FAIL+1)); FAILED+=("$1"); }

assert_eq() { # name expected actual
    if [[ "$2" == "$3" ]]; then ok "$1"; else
        bad "$1"; printf '      expected: [%s]\n      actual:   [%s]\n' "$2" "$3"; fi
}
assert_contains() { # name haystack needle
    if [[ "$2" == *"$3"* ]]; then ok "$1"; else
        bad "$1"; printf '      missing substring: [%s]\n' "$3"; fi
}
assert_not_contains() { # name haystack needle
    if [[ "$2" != *"$3"* ]]; then ok "$1"; else
        bad "$1"; printf '      unexpected substring: [%s]\n' "$3"; fi
}

# Print the body of shell function $2 as defined in file $1 (top-level `name() {`
# ... matching `}` in column 0). Used to test real code in isolation.
extract() { sed -n "/^$2() {/,/^}/p" "$1"; }

#===============================================================================
section "Syntax (bash -n)"
#===============================================================================
for f in "$CB" "$CM" "$INSTALL" "${BASH_SOURCE[0]}"; do
    if /bin/bash -n "$f" 2>/dev/null; then ok "bash -n $(basename "$f")"
    else bad "bash -n $(basename "$f")"; fi
done

#===============================================================================
section "html_escape (bash 5.2 patsub-safe)"
#===============================================================================
# Test the real helper from BOTH scripts (they must stay in sync and correct).
for src in "$CB" "$CM"; do
    name="$(basename "$src")"
    run_escape() { # input -> escaped, via the extracted function under /bin/bash
        { extract "$src" html_escape
          printf 'html_escape %q\n' "$1"
          printf 'printf "%%s" "$_ESC"\n'
        } | /bin/bash
    }
    assert_eq "[$name] & -> &amp;"          "AT&amp;T"            "$(run_escape 'AT&T')"
    assert_eq "[$name] < -> &lt;"           "a&lt;b"              "$(run_escape 'a<b')"
    assert_eq "[$name] > -> &gt;"           "c &gt; d"            "$(run_escape 'c > d')"
    assert_eq "[$name] && preserved"        "x &amp;&amp; y"      "$(run_escape 'x && y')"
    assert_eq "[$name] combined"            "&lt;a&gt; &amp; b"   "$(run_escape '<a> & b')"
    assert_eq "[$name] no double-escape"    "&amp;amp;"           "$(run_escape '&amp;')"
    assert_eq "[$name] empty"               ""                    "$(run_escape '')"
    assert_eq "[$name] plain untouched"     "sshd"                "$(run_escape 'sshd')"
done

#===============================================================================
section "get_active_sessions (real fn, stubbed w/ss/loginctl)"
#===============================================================================
{
    echo 'set -uo pipefail'
    echo 'SERVER_NAME="testhost"; SSH_PORT="22"'
    extract "$CB" html_escape
    extract "$CB" get_active_sessions
    cat <<'STUBS'
w() { printf '%s\n' 'alice    pts/0    1.2.3.4    10:00    0.00s  0.1s  0.0s  vim a<b>c & d.txt'; }
ss() { printf '%s\n' \
  'ESTAB 0 0 10.0.0.1:22 1.2.3.40:51000 users:(("sshd",pid=111,fd=4))' \
  'ESTAB 0 0 10.0.0.1:22 1.2.3.4:51001 users:(("sshd",pid=222,fd=4))' \
  'ESTAB 0 0 10.0.0.1:22 1.2.3.4:51002 users:(("sshd",pid=333,fd=4))' \
  'ESTAB 0 0 [2001:db8::1]:22 [2406:da00::5]:40000 users:(("sshd",pid=444,fd=4))'; }
loginctl() {
  case "$1" in
    list-sessions) printf '%s\n' '2 1000 alice seat0 tty2 active no -' 'c1 1001 bob - - active no -' ;;
    show-session) case "$2" in
        2)  printf '%s\n' 'Name=alice' 'Type=tty' 'Class=user' 'State=active' 'Remote=no' 'Service=login' 'TTY=tty2' ;;
        c1) printf '%s\n' 'Name=bob' 'Type=tty' 'Class=user' 'State=active' 'Remote=yes' 'RemoteHost=9.9.9.9' 'Service=sshd' 'TTY=pts/1' ;;
      esac ;;
  esac
}
command() { [[ "${2:-}" == loginctl ]] && return 0; builtin command "$@"; }
date() { echo '2026-01-01 00:00:00'; }
get_active_sessions
STUBS
} > "$TMP/gas.sh"
GAS="$(/bin/bash "$TMP/gas.sh")"

assert_contains     "command < > & HTML-escaped"   "$GAS" "vim a&lt;b&gt;c &amp; d.txt"
assert_not_contains "no raw '<b>' from command"    "$GAS" "a<b>c"
assert_contains     "IPv6 peer parsed (brackets stripped)" "$GAS" "2406:da00::5</code>:40000"
assert_contains     "dedup keeps 1.2.3.4"          "$GAS" "1.2.3.4</code>:51001"
assert_not_contains "dedup drops 2nd 1.2.3.4"      "$GAS" "51002"
assert_contains     "1.2.3.40 not confused w/ 1.2.3.4" "$GAS" "1.2.3.40</code>:51000"
assert_contains     "alphanumeric session id 'c1'" "$GAS" "#c1"
assert_contains     "remote session shows host"    "$GAS" "From: <code>9.9.9.9</code>"
assert_contains     "remote session uses SSH icon" "$GAS" "🔑 #c1"
assert_contains     "total = 1 interactive + 3 ssh" "$GAS" "Total: 4 active"

#===============================================================================
section "kick_ip (Block also terminates sessions from the IP)"
#===============================================================================
kick_ip_run() { # $1 = ip
    {
        printf 'set -o pipefail\n'
        extract "$CB" kick_ip
        cat <<'STUBS'
log(){ :; }
command(){ [[ "${2:-}" == loginctl ]] && return 0; builtin command "$@"; }
loginctl(){
  case "$1" in
    list-sessions)     printf '%s\n' '10 1000 alice seat0 pts/0 active no -' '20 1001 bob - pts/1 active no -' ;;
    show-session)      case "$2" in 10) echo 1.2.3.4 ;; 20) echo 9.9.9.9 ;; esac ;;
    terminate-session) echo "TERM $2" ;;
  esac
}
ss(){ printf '%s\n' 'ESTAB 0 0 10.0.0.1:22 1.2.3.4:55000 users:(("sshd",pid=4242,fd=4))'; }
kill(){ echo "KILL $*"; }
STUBS
        printf 'kick_ip %q; echo "rc=$?"\n' "$1"
    } | /bin/bash
}
KI="$(kick_ip_run 1.2.3.4)"
assert_contains     "terminates logind session with matching RemoteHost" "$KI" "TERM 10"
assert_not_contains "leaves session with different RemoteHost"           "$KI" "TERM 20"
assert_contains     "kills sshd process whose peer is the IP"            "$KI" "KILL -9 4242"
assert_contains     "reports success when something was terminated"      "$KI" "rc=0"
KI_LO="$(kick_ip_run 127.0.0.1)"
assert_not_contains "refuses loopback (no terminate)"                    "$KI_LO" "TERM"
assert_contains     "refuses loopback (rc=1)"                            "$KI_LO" "rc=1"

#===============================================================================
section "connection-monitor alert builds valid JSON (AT&T case)"
#===============================================================================
{
    extract "$CM" html_escape
    extract "$CM" json_escape
    cat <<'BODY'
user='ev<il>'; client_ip='1.2.3.4'
geo_info='United States, Dallas, AT&T Services'
connection_type='SSH'; tty='pts/0'
_ESC=""
html_escape "$user";      e_user="$_ESC"
html_escape "$geo_info";  e_geo="$_ESC"
msg="🔑 <b>Alert</b>
👤 <b>User:</b> <code>${e_user}</code>
📍 <b>Location:</b> ${e_geo}"
printf '%s' "$msg" | json_escape
BODY
} > "$TMP/cm.sh"
CM_JSON="$(/bin/bash "$TMP/cm.sh")"

JSON_CHECK="$(printf '%s' "$CM_JSON" | python3 -c '
import json,sys
s=json.loads(sys.stdin.read())          # raises if invalid JSON
assert "AT&amp;T" in s, "geo & not escaped"
assert "ev&lt;il&gt;" in s, "user <> not escaped"
assert "ev<il>" not in s, "raw <> leaked"
assert "<b>" in s and "<code>" in s, "intended tags lost"
print("ok")
' 2>&1)"
assert_eq "valid JSON + entities escaped + tags kept" "ok" "$JSON_CHECK"

#===============================================================================
section "connection-monitor false-positive filtering"
#===============================================================================
# Run the real send_connection_alert with its heavy callees stubbed; the
# send_telegram_message stub prints SENT, so an empty result means "skipped".
fp_run() { # $1=PAM_SERVICE  $2=client_ip  $3=NOTIFY_LOCAL
    {
        printf 'set -uo pipefail\n'
        printf 'SERVER_NAME=t; SERVER_IP=1; DEDUP_WINDOW=0; GEO_LOOKUP=false\n'
        printf 'IGNORED_SERVICES=%q\n' 'cron crond sudo su su-l runuser runuser-l systemd-user polkit-1 passwd chpasswd chsh chfn newgrp gdm-password gdm-launch-environment lightdm sddm xdm'
        printf 'NOTIFY_LOCAL=%q\n' "$3"
        printf 'PAM_SERVICE=%q; PAM_USER=tester; PAM_TYPE=open_session; PAM_TTY=pts/0\n' "$1"
        extract "$CM" html_escape
        extract "$CM" send_connection_alert
        printf 'log(){ :; }\n'
        printf 'is_duplicate(){ return 1; }\n'
        printf 'get_client_ip(){ printf %%s %q; }\n' "$2"
        printf 'get_connection_type(){ printf SSH; }\n'
        printf 'get_geo_info(){ printf x; }\n'
        printf 'create_inline_keyboard(){ printf "{}"; }\n'
        printf 'send_telegram_message(){ printf SENT; }\n'
        printf 'send_connection_alert\n'
    } > "$TMP/fp.sh"
    /bin/bash "$TMP/fp.sh"
}
assert_eq "sshd remote login -> ALERT"          "SENT" "$(fp_run sshd 1.2.3.4 true)"
assert_eq "cron session -> skipped"             ""     "$(fp_run cron 1.2.3.4 true)"
assert_eq "sudo session -> skipped"             ""     "$(fp_run sudo 1.2.3.4 true)"
assert_eq "su session -> skipped"               ""     "$(fp_run su 1.2.3.4 true)"
assert_eq "systemd-user session -> skipped"     ""     "$(fp_run systemd-user 1.2.3.4 true)"
assert_eq "local TTY + NOTIFY_LOCAL=false -> skipped" "" "$(fp_run login Local/Unknown false)"
assert_eq "local TTY + NOTIFY_LOCAL=true  -> ALERT"  "SENT" "$(fp_run login Local/Unknown true)"
assert_eq "remote sshd + NOTIFY_LOCAL=false -> ALERT" "SENT" "$(fp_run sshd 1.2.3.4 false)"

#===============================================================================
section "install.sh fetch() selects curl or wget"
#===============================================================================
fetch_with() { # $1 = stub setup snippet
    { extract "$INSTALL" fetch
      echo "$1"
      echo 'fetch "http://example/x" "/tmp/out"; echo "rc=$?"'
    } | /bin/bash 2>&1
}
out="$(fetch_with '
command() { case "${2:-}" in curl) return 0;; *) builtin command "$@";; esac; }
curl() { echo "USED_CURL $*"; }')"
assert_contains "uses curl when present" "$out" "USED_CURL"

out="$(fetch_with '
command() { case "${2:-}" in curl) return 1;; wget) return 0;; *) builtin command "$@";; esac; }
wget() { echo "USED_WGET $*"; }')"
assert_contains "falls back to wget when no curl" "$out" "USED_WGET"
assert_contains "wget invoked with -O <out> <url>" "$out" "USED_WGET -q -O /tmp/out http://example/x"

out="$(fetch_with 'command() { return 1; }')"
assert_contains "returns 127 when neither tool exists" "$out" "rc=127"

#===============================================================================
section "install.sh esc_sed() protects config writes from metacharacters"
#===============================================================================
# Round-trip a credential through the exact sed write used by interactive_setup
# and read the value back; must survive &, |, and \.
cred_roundtrip() {
    { extract "$INSTALL" esc_sed
      cat <<BODY
val=$(printf '%q' "$1")
line='TELEGRAM_BOT_TOKEN=""'
out=\$(printf '%s\n' "\$line" | sed "s|^TELEGRAM_BOT_TOKEN=.*|TELEGRAM_BOT_TOKEN=\\"\$(esc_sed "\$val")\\"|")
got=\${out#TELEGRAM_BOT_TOKEN=\\"}; got=\${got%\\"}
printf '%s' "\$got"
BODY
    } | /bin/bash
}
assert_eq "normal token round-trips"   '123456:ABC-def_x'  "$(cred_roundtrip '123456:ABC-def_x')"
assert_eq "group chat id round-trips"  '-1001234567890'    "$(cred_roundtrip '-1001234567890')"
assert_eq "ampersand round-trips"      '123:AB&CD'         "$(cred_roundtrip '123:AB&CD')"
assert_eq "pipe (delimiter) round-trips" '123:AB|CD'       "$(cred_roundtrip '123:AB|CD')"
assert_eq "backslash round-trips"      '123:AB\CD'         "$(cred_roundtrip '123:AB\CD')"

#===============================================================================
section "install.sh runs when piped via stdin (curl|bash)"
#===============================================================================
# Reproduces `curl ... | bash -s help`: no real file, so BASH_SOURCE is empty.
# Must not emit a `set -u` unbound-variable error and must still run.
piped_out="$(/bin/bash -s help < "$INSTALL" 2>&1)"
assert_not_contains "no 'unbound variable' when piped" "$piped_out" "unbound variable"
assert_contains     "piped help still renders version" "$piped_out" "Version"

#===============================================================================
section "install.sh ask() is non-interactive safe (curl|bash)"
#===============================================================================
ask_run() { # $1 = setup, returns the captured variable value
    timeout 5 /bin/bash -c "
        $(extract "$INSTALL" ask)
        $1
        ask 'Prompt? ' answer 'THEDEFAULT'
        printf '%s' \"\$answer\"
    " </dev/null 2>/dev/null
}
assert_eq "ASSUME_YES=true -> default, no prompt" "THEDEFAULT" "$(ask_run 'ASSUME_YES=true')"
# No terminal available (stdin=/dev/null, no controlling tty) -> default, no hang
assert_eq "no tty -> falls back to default"       "THEDEFAULT" "$(ask_run 'ASSUME_YES=false')"

#===============================================================================
section "Optional: shellcheck"
#===============================================================================
if command -v shellcheck >/dev/null 2>&1; then
    for f in "$CB" "$CM" "$INSTALL"; do
        if shellcheck -S warning "$f" >/dev/null 2>&1; then ok "shellcheck $(basename "$f")"
        else bad "shellcheck $(basename "$f") (run: shellcheck $f)"; fi
    done
else
    printf '  (shellcheck not installed - skipped)\n'
fi

#===============================================================================
# Summary
#===============================================================================
printf '\n%s─────────────────────────────%s\n' "$CYAN" "$NC"
printf 'Total: %d  %sPassed: %d%s  %sFailed: %d%s\n' \
    "$((PASS+FAIL))" "$GREEN" "$PASS" "$NC" "$RED" "$FAIL" "$NC"
if (( FAIL > 0 )); then
    printf '\nFailed tests:\n'
    for t in "${FAILED[@]}"; do printf '  - %s\n' "$t"; done
    exit 1
fi
printf '%sAll tests passed.%s\n' "$GREEN" "$NC"
