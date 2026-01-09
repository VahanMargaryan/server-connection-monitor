# Server Connection Monitor

Real-time Telegram notifications for SSH and server connections with inline action buttons to block IPs or kick users directly from your phone.

## Features

- **Real-time Alerts** - Instant Telegram notifications when someone connects
- **Geo-location** - See where connections originate
- **Multiple Connection Types** - SSH, tunnels, rsync, SCP, SFTP, local logins
- **Inline Actions** - Block IP or kick user directly from Telegram
- **Multi-server Support** - Deploy on multiple servers with unique identification
- **Security Integration** - Works with iptables, hosts.deny, and fail2ban

## Quick Start

### 1. Create a Telegram Bot

1. Open Telegram and search for **@BotFather**
2. Send `/newbot` and follow the prompts
3. Save the **Bot Token** provided

### 2. Get Your Chat ID

1. Search for **@userinfobot** in Telegram
2. Start the bot to see your Chat ID
3. For group notifications, add your bot to a group first

### 3. Install

**One-line installation:**

```bash
curl -fsSL https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh | sudo bash
```

Or with wget:

```bash
wget -qO- https://raw.githubusercontent.com/VahanMargaryan/server-connection-monitor/main/install.sh | sudo bash
```

**Manual installation:**

```bash
git clone https://github.com/VahanMargaryan/server-connection-monitor.git
cd server-connection-monitor
sudo ./install.sh
```

### 4. Configure

During installation, you'll be prompted for your Bot Token and Chat ID. Or edit manually:

```bash
sudo nano /etc/connection-monitor/config.conf
```

### 5. Test

```bash
sudo connection-monitor test
```

## Installation Commands

The unified installer supports multiple commands:

```bash
sudo ./install.sh install    # Fresh installation (default)
sudo ./install.sh update     # Update existing installation
sudo ./install.sh fix        # Fix duplicate notifications
sudo ./install.sh uninstall  # Remove installation
sudo ./install.sh test       # Test Telegram notification
sudo ./install.sh status     # Show installation status
sudo ./install.sh help       # Show help
```

## Notification Example

When someone connects, you receive:

```
🔑 New Connection Alert

🖥️ Server: prod-server-01
🌐 Server IP: 203.0.113.10

👤 User: admin
📡 Client IP: 198.51.100.50
📍 Location: United States, New York, Comcast
🔌 Type: SSH
📺 TTY: pts/0
🕐 Time: 2024-01-15 14:30:25 UTC
🔢 Session: 12345

[🚫 Block IP] [👢 Kick User]
[📋 Show Active Sessions]
```

## Configuration

Edit `/etc/connection-monitor/config.conf`:

```bash
# Required
TELEGRAM_BOT_TOKEN="your-bot-token"
TELEGRAM_CHAT_ID="your-chat-id"

# Optional
SERVER_NAME=""              # Custom name (auto-detected if empty)
EXCLUDED_USERS="backup"     # Space-separated users to ignore
EXCLUDED_IPS="10.0.0.1"     # Space-separated IPs to ignore
DEDUP_WINDOW="10"           # Seconds to suppress duplicate notifications
GEO_LOOKUP="true"           # Enable IP geo-location
DEBUG="false"               # Enable debug logging
```

## Connection Types

| Type | Icon | Description |
|------|------|-------------|
| SSH | 🔑 | Standard SSH login |
| SSH Tunnel | 🚇 | Port forwarding without shell |
| rsync | 📦 | rsync over SSH |
| SCP/SFTP | 📁 | File transfers |
| Local Login | 🖥️ | Console/TTY login |
| sudo | ⚡ | Privilege escalation |
| su | 👤 | User switching |

## Inline Button Actions

### 🚫 Block IP
- Adds IP to iptables DROP rule
- Adds to `/etc/hosts.deny`
- Integrates with fail2ban if installed
- Rules persist across reboots

### 👢 Kick User
- Terminates active sessions via loginctl
- Kills SSH connections from the IP
- Closes all PTY sessions for the user

### 📋 Show Active Sessions
- Lists all currently logged-in users
- Shows TTY, connection source, and time

## File Locations

| File | Purpose |
|------|---------|
| `/usr/local/bin/connection-monitor` | Main notification script |
| `/usr/local/bin/connection-monitor-handler` | Telegram callback handler |
| `/etc/connection-monitor/config.conf` | Configuration file |
| `/var/log/connection-monitor.log` | Notification logs |
| `/var/log/connection-monitor-handler.log` | Handler logs |
| `/var/lib/connection-monitor/` | State data |

## Commands Reference

```bash
# Test notification
sudo connection-monitor test

# Check service status
sudo systemctl status connection-monitor-handler

# View handler logs (real-time)
sudo journalctl -u connection-monitor-handler -f

# View notification logs
sudo tail -f /var/log/connection-monitor.log

# Restart the handler
sudo systemctl restart connection-monitor-handler

# Edit configuration
sudo nano /etc/connection-monitor/config.conf
```

## How It Works

1. **PAM Integration** - The script hooks into PAM to detect login events
2. **Connection Detection** - Identifies connection type and source IP
3. **Telegram Notification** - Sends alert via Bot API with inline keyboard
4. **Callback Handling** - Background daemon polls for button presses
5. **Action Execution** - Block/kick commands run with root privileges

## Multi-Server Deployment

Deploy on multiple servers by:

1. Installing on each server
2. Using unique `SERVER_NAME` for each
3. Using the same bot token and chat ID

Each notification identifies which server sent it. Button actions are routed to the correct server.

## Troubleshooting

### Notifications not sending

```bash
sudo connection-monitor test
cat /etc/connection-monitor/config.conf
sudo tail -f /var/log/connection-monitor.log
```

### Buttons not working

```bash
sudo systemctl status connection-monitor-handler
sudo journalctl -u connection-monitor-handler -f
sudo systemctl restart connection-monitor-handler
```

### Duplicate notifications

```bash
sudo ./install.sh fix
```

### PAM not triggering

```bash
grep connection-monitor /etc/pam.d/sshd
sudo systemctl restart sshd
```

## Requirements

- Linux (Debian/Ubuntu/RHEL)
- Bash 4.0+
- curl
- Python 3
- iptables
- systemd

## Security Considerations

- Configuration file has restricted permissions (600)
- Bot token is kept server-side only
- Actions validate server name to prevent cross-server attacks
- Callback handler validates chat ID before executing
- All actions are logged

## License

MIT License
