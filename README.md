```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
                 [ FIREWALL SENTINEL v1.0 ]
         They scan you. You block them. Then you scan back.
```

<div align="center">

![bash](https://img.shields.io/badge/bash-5.0%2B-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![iptables](https://img.shields.io/badge/iptables-required-FF6B6B?style=for-the-badge)
![nmap](https://img.shields.io/badge/nmap-required-00B4D8?style=for-the-badge)
![license](https://img.shields.io/badge/license-MIT-yellow?style=for-the-badge)
![platform](https://img.shields.io/badge/platform-linux-0078D4?style=for-the-badge&logo=linux&logoColor=white)
![defcon](https://img.shields.io/badge/born%20at-DEF%20CON-red?style=for-the-badge)

**Scan detection. Instant block. Automatic counter-reconnaissance.**  
*A firewall that hits back.*

</div>

---

## ⚡ What Is This?

**Firewall Sentinel** is a Linux bash script that monitors your host for port scans and automated attack attempts in real time. The moment a scanner crosses your threshold — it gets **blocked at the kernel level** via `iptables`, then **immediately counter-scanned** with `nmap`, `whois`, and reverse DNS lookups.

> Born from a DEF CON demo script. Rebuilt from memory. Made production-ready.

You find out *who* is scanning you, *what* they're running, and *where* they're coming from — while they're sitting behind a DROP rule wondering why you went quiet.

---

## 🎯 Core Flow

```
 Attacker probes your ports
         │
         ▼
 iptables LOG → syslog stream
         │
         ▼
 Sentinel counts hits per IP
 within rolling TIME_WINDOW
         │
    threshold hit?
         │
    ┌────┴────┐
    ▼         ▼
  BLOCK     ignore
 (iptables
  DROP rule)
    │
    ▼
 Counter-scan fires in background:
  ├─ nmap -sV --script=default,vuln
  ├─ whois (org, netblock, abuse contact)
  └─ reverse DNS PTR lookup
         │
         ▼
 Full report saved to:
 /var/log/sentinel/scans/<ip>.txt
```

---

## 🚀 Quick Start

### 1. Clone & install

```bash
git clone https://github.com/yourusername/firewall-sentinel.git
cd firewall-sentinel
chmod +x firewall_sentinel.sh
```

### 2. Install dependencies

```bash
# Debian/Ubuntu
sudo apt install iptables nmap whois

# RHEL/CentOS/Fedora
sudo dnf install iptables nmap whois
```

### 3. Whitelist yourself first ⚠️

```bash
sudo ./firewall_sentinel.sh whitelist YOUR_IP
```

> **Don't skip this.** If your own IP hits threshold during testing, you'll block yourself out.

### 4. Start Sentinel

```bash
sudo ./firewall_sentinel.sh start
```

That's it. Sentinel initializes its `iptables` chain, starts tailing syslog, and begins watching.

---

## 🛠️ Configuration

All tunable parameters live at the top of the script:

| Variable | Default | Description |
|---|---|---|
| `SCAN_THRESHOLD` | `15` | Hits within `TIME_WINDOW` before blocking triggers |
| `TIME_WINDOW` | `60` | Rolling window in seconds |
| `COUNTER_SCAN_LEVEL` | `-sV --script=default,vuln` | nmap scan flags |
| `MONITOR_IFACE` | `eth0` | Your network interface |
| `MAX_COUNTER_THREADS` | `3` | Max parallel counter-scans |
| `LOG_FILE` | `/var/log/sentinel.log` | Main log path |
| `BLOCK_LIST` | `/etc/sentinel/blocked.txt` | Persistent block list |
| `WHITELIST` | `/etc/sentinel/whitelist.txt` | Never-block list |

### Adjust aggression

```bash
# Stealth / production (slower, quieter nmap)
COUNTER_SCAN_LEVEL="-sV -T2 --open"

# Default (balanced)
COUNTER_SCAN_LEVEL="-sV --script=default,vuln -T4"

# Full aggression (loud, thorough)
COUNTER_SCAN_LEVEL="-A --script=all -T5"
```

---

## 📋 Commands

```bash
sudo ./firewall_sentinel.sh start              # Initialize and begin monitoring
sudo ./firewall_sentinel.sh stop               # Flush all rules and exit cleanly
sudo ./firewall_sentinel.sh status             # Show chain state + last 10 blocks
sudo ./firewall_sentinel.sh block   <ip>       # Manually block an IP
sudo ./firewall_sentinel.sh unblock <ip>       # Remove a block
sudo ./firewall_sentinel.sh scan    <ip>       # Manually trigger counter-scan
sudo ./firewall_sentinel.sh whitelist <ip>     # Add IP to permanent whitelist
sudo ./firewall_sentinel.sh log                # Tail the live log
```

---

## 📁 File Structure

```
/etc/sentinel/
├── blocked.txt          # All blocked IPs with timestamps + reasons
└── whitelist.txt        # IPs that will never be blocked

/var/log/
├── sentinel.log         # Main event log
└── sentinel/scans/
    └── 1.2.3.4_<ts>.txt # Full counter-scan report per attacker
```

---

## 📊 Sample Output

**Terminal while running:**
```
[+] Sentinel started. Watching eth0...
[*] Watching syslog for SENTINEL events...
[~] 45.33.32.156: 7 hits in 12s (threshold=15)
[~] 45.33.32.156: 12 hits in 18s (threshold=15)
[~] 45.33.32.156: 15 hits in 23s (threshold=15)
[!] BLOCKED: 45.33.32.156
[~] Counter-scanning 45.33.32.156 ...
[+] Counter-scan saved: /var/log/sentinel/scans/45.33.32.156_1718123456.txt
--- SCAN SUMMARY: 45.33.32.156 ---
OrgName: DigitalOcean, LLC
22/tcp   open  ssh     OpenSSH 8.2p1
80/tcp   open  http    nginx 1.18.0
443/tcp  open  https
```

**Counter-scan report excerpt:**
```
==============================
 COUNTER-SCAN REPORT
 Target : 45.33.32.156
 Time   : Tue May 12 14:32:11 UTC 2026
==============================

--- WHOIS ---
OrgName: DigitalOcean, LLC
Country: US
CIDR: 45.33.0.0/16
abuse: abuse@digitalocean.com

--- NMAP ---
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http     nginx 1.18.0
3306/tcp open  mysql    MySQL 5.7.42

--- REVERSE DNS ---
45.33.32.156.in-addr.arpa domain name pointer scanme.nmap.org.
```

---

## 🧠 How Detection Works

Sentinel uses **iptables kernel-level logging** piped through syslog rather than packet sniffing. This means:

- Zero performance overhead on the data path
- Detection happens on actual TCP connection attempts (state `NEW`)
- Works across all ports simultaneously — no port-specific rules needed
- Rolling window resets automatically — bursty-but-legitimate traffic won't trip it

The `SENTINEL` iptables chain is inserted at the **top of INPUT**, so it evaluates before any other rules.

---

## 🔒 Security Notes

- **Run as root** — required for iptables and raw log access
- **Whitelist your IP first** — the script auto-whitelists `127.0.0.1`
- **Counter-scanning is active recon** — know your local laws before pointing this at foreign IPs. In most jurisdictions, scanning an IP that scanned you first is defensible, but YMMV. Use responsibly.
- **Persistent blocks** — `blocked.txt` survives restarts; re-running `start` will not automatically re-apply old blocks. You can script that via `iptables-restore` if needed.
- **nmap `--script=vuln`** — this runs NSE scripts that may be noisy. Adjust `COUNTER_SCAN_LEVEL` to `-sV` only if you want quieter recon.

---

## 🔧 Systemd Service (Optional)

Run Sentinel as a persistent background service:

```ini
# /etc/systemd/system/sentinel.service
[Unit]
Description=Firewall Sentinel - Scan Detection & Counter-Recon
After=network.target

[Service]
Type=simple
ExecStart=/path/to/firewall_sentinel.sh start
ExecStop=/path/to/firewall_sentinel.sh stop
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel
sudo systemctl status sentinel
```

---

## 🪛 Troubleshooting

**No events firing?**  
Check your syslog path. Sentinel auto-detects `/var/log/kern.log`, `/var/log/syslog`, `/var/log/messages` — make sure one exists and iptables LOG rules are writing to it:
```bash
sudo iptables -L SENTINEL -n -v
sudo tail -f /var/log/kern.log | grep SENTINEL
```

**Wrong interface?**  
Find yours with `ip link show` and update `MONITOR_IFACE`.

**Blocked yourself?**  
```bash
sudo iptables -D SENTINEL -s YOUR_IP -j DROP
```

**Counter-scan is too slow?**  
Reduce nmap intensity: change `COUNTER_SCAN_LEVEL` to `-sV -T3 --open`

---

## 📜 History

This script is a faithful rebuild of a firewall demo circulated at **DEF CON** — one of those "someone handed me a USB at a talk" moments. The original concept was elegant: most intrusion detection stops at blocking. This one turns the table and conducts instant passive intelligence gathering on anyone dumb enough to probe you.

Rebuilt from memory. Modernized for bash 5+, iptables nft compatibility, and production Linux systems.

---

## 🤝 Contributing

PRs welcome. Ideas worth contributing:

- `ip6tables` / IPv6 support
- Fail2ban integration mode
- Slack/Discord webhook alerts on block events  
- GeoIP lookup in counter-scan reports
- Web dashboard for scan report viewing

---

## ⚖️ License

MIT — do what you want, don't blame me if you scan the wrong box.

---

<div align="center">

*"The best defense is knowing exactly who's attacking you."*

**⭐ Star this if you've ever been port-scanned at 3am ⭐**

</div>
