# Server Connection Monitor

Real-time Telegram alerts for SSH / server logins, with inline buttons to block or
unblock an IP and kick a user straight from your phone.

## Features

- Instant alert on every connection — SSH, tunnels, rsync, SCP/SFTP, console
- Inline buttons: **Block IP · Unblock IP · Kick User · Show Active Sessions**
- IP geolocation, multi-server support, `iptables` / `hosts.deny` / `fail2ban` integration
- Noise control: ignores `cron`/`sudo`/`su`/`systemd` sessions, optional remote-only mode

## Install

1. Create a bot with [@BotFather](https://t.me/BotFather) (`/newbot`) and copy the **token**.
2. Get your **chat ID** from [@userinfobot](https://t.me/userinfobot).
3. Run the installer — it downloads everything and prompts for the token/chat ID
   (even when piped):

```bash
curl -fsSL https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh | sudo bash
```

`wget -qO- <same-url> | sudo bash` works too. **Unattended** (no prompts):

```bash
curl -fsSL https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh \
  | sudo TELEGRAM_BOT_TOKEN="123456:ABC-DEF..." TELEGRAM_CHAT_ID="987654321" bash
```

From a checkout: `git clone …/server-connection-monitor.git && cd server-connection-monitor && sudo ./install.sh`

Then test it: `sudo connection-monitor test`

## Managing

Run any command remotely (no checkout needed) by appending it after `bash -s`:

```bash
curl -fsSL https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh | sudo bash -s update
curl -fsSL https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh | sudo bash -s uninstall
```

From a checkout: `sudo ./install.sh {install|update|fix|uninstall|test|status|help}`

```bash
sudo systemctl status connection-monitor-handler     # daemon status
sudo journalctl -u connection-monitor-handler -f     # button/handler logs
sudo tail -f /var/log/connection-monitor.log         # alert logs
```

## Configuration

Edit `/etc/connection-monitor/config.conf`:

```bash
TELEGRAM_BOT_TOKEN="..."     # required
TELEGRAM_CHAT_ID="..."       # required

SERVER_NAME=""               # label shown in alerts (auto-detected if empty)
SSH_PORT="22"                # port used when listing active SSH connections
EXCLUDED_USERS="backup"      # users to never alert on (space-separated)
EXCLUDED_IPS="10.0.0.1"      # IPs to never alert on (space-separated)
IGNORED_SERVICES="cron sudo su systemd-user ..."  # PAM services that never alert
NOTIFY_LOCAL="true"          # false = alert only on remote (network) logins
DEDUP_WINDOW="10"            # seconds to suppress duplicate alerts
GEO_LOOKUP="true"            # IP geolocation
DEBUG="false"
```

`IGNORED_SERVICES` and `NOTIFY_LOCAL` suppress false positives from cron jobs,
privilege escalation and local console/TTY sessions. After editing, run
`sudo systemctl restart connection-monitor-handler`.

## Example alert

```
🔑 New Connection Alert
🖥️ Server: prod-01        📡 Client IP: 198.51.100.50
👤 User: admin            📍 Location: New York, Comcast
🔌 Type: SSH              🕐 2026-01-15 14:30:25 UTC

[🚫 Block IP] [👢 Kick User] [📋 Show Active Sessions]
```

## How it works

A PAM hook in `/etc/pam.d/sshd` runs the monitor on each login and sends the
alert. A small systemd daemon long-polls Telegram and executes button actions as
root — block/unblock via `iptables` + `hosts.deny` + `fail2ban`, kick via
`loginctl`. For multiple servers, give each a unique `SERVER_NAME` and reuse the
same bot/chat; actions are routed back to the correct host.

## Troubleshooting

```bash
sudo connection-monitor test                        # no alerts? test + check logs
sudo systemctl restart connection-monitor-handler   # buttons dead? restart daemon
sudo ./install.sh fix                                # duplicate alerts
grep connection-monitor /etc/pam.d/sshd             # PAM not triggering?
```

## Testing

`./tests/run-tests.sh` — self-contained suite, no root/network required (system
commands are stubbed). See [`tests/README.md`](tests/README.md).

## Requirements

Linux (Debian/Ubuntu/RHEL), bash 4+, curl (or wget for the installer), Python 3,
iptables, systemd.

## Security

Config file is `600`; the bot token stays server-side; the handler validates the
chat ID and server name before acting; user/network-supplied values are
HTML-escaped before sending; all actions are logged.

## License

MIT
