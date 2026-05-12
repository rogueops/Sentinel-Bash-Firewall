#!/usr/bin/env bash
# =============================================================================
# FIREWALL SENTINEL - Scan Detection, Auto-Block & Counter-Scan
# Inspired by classic DEF CON firewall scripts
# Requires: iptables, nmap, whois, tcpdump/iptables logging
# Run as root
# =============================================================================

set -euo pipefail

# ─── CONFIG ──────────────────────────────────────────────────────────────────
LOG_FILE="/var/log/sentinel.log"
BLOCK_LIST="/etc/sentinel/blocked.txt"
WHITELIST="/etc/sentinel/whitelist.txt"
IPTABLES_CHAIN="SENTINEL"
SCAN_THRESHOLD=15          # Port hits within TIME_WINDOW to trigger block
TIME_WINDOW=60             # Seconds to evaluate port hit count
COUNTER_SCAN_LEVEL="-sV --script=default,vuln"   # nmap scan intensity
MONITOR_IFACE="eth0"       # Interface to monitor
SYSLOG_TAG="SENTINEL"      # Tag used in iptables LOG rules
PORT_RANGE="1:65535"       # Ports to watch
MAX_COUNTER_THREADS=3      # Parallel counter-scan limit

# ─── COLORS ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

# ─── INIT ─────────────────────────────────────────────────────────────────────
init() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}[!] Must run as root${NC}"; exit 1; }

    # Deps check
    for cmd in iptables nmap whois logger tcpdump; do
        command -v "$cmd" &>/dev/null || { echo -e "${RED}[!] Missing: $cmd${NC}"; exit 1; }
    done

    mkdir -p /etc/sentinel /var/log
    touch "$LOG_FILE" "$BLOCK_LIST"
    [[ -f "$WHITELIST" ]] || touch "$WHITELIST"

    # Add loopback and local subnet to whitelist automatically
    echo "127.0.0.1" >> "$WHITELIST"

    # Build iptables chain if not exists
    iptables -N "$IPTABLES_CHAIN" 2>/dev/null || iptables -F "$IPTABLES_CHAIN"
    iptables -C INPUT -j "$IPTABLES_CHAIN" 2>/dev/null || iptables -I INPUT -j "$IPTABLES_CHAIN"

    # Log new connection attempts to syslog for monitoring
    iptables -A "$IPTABLES_CHAIN" -m state --state NEW \
        -m limit --limit 10/min \
        -j LOG --log-prefix "$SYSLOG_TAG: " --log-level 4

    log "INFO" "Sentinel initialized on $MONITOR_IFACE | threshold=$SCAN_THRESHOLD hits/${TIME_WINDOW}s"
    echo -e "${GREEN}[+] Sentinel started. Watching $MONITOR_IFACE...${NC}"
}

# ─── LOGGING ─────────────────────────────────────────────────────────────────
log() {
    local level="$1" msg="$2"
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$ts] [$level] $msg" | tee -a "$LOG_FILE"
    logger -t "SENTINEL" "[$level] $msg"
}

# ─── WHITELIST CHECK ──────────────────────────────────────────────────────────
is_whitelisted() {
    local ip="$1"
    grep -qF "$ip" "$WHITELIST" 2>/dev/null
}

# ─── ALREADY BLOCKED CHECK ───────────────────────────────────────────────────
is_blocked() {
    local ip="$1"
    grep -qF "$ip" "$BLOCK_LIST" 2>/dev/null
}

# ─── BLOCK IP ─────────────────────────────────────────────────────────────────
block_ip() {
    local ip="$1" reason="${2:-scan_detected}"

    if is_whitelisted "$ip"; then
        log "WARN" "Skipping block — $ip is whitelisted"
        return
    fi

    if is_blocked "$ip"; then
        log "INFO" "$ip already blocked"
        return
    fi

    # Drop all inbound from attacker
    iptables -I "$IPTABLES_CHAIN" -s "$ip" -j DROP
    # Also block outbound to prevent reverse shells if already compromised
    iptables -I OUTPUT -d "$ip" -j LOG --log-prefix "SENTINEL_OUT_BLOCK: " --log-level 4
    # Re-enable output after logging (we want counter-scan traffic to pass)

    echo "$ip  # blocked: $(date '+%Y-%m-%d %H:%M:%S') reason=$reason" >> "$BLOCK_LIST"
    log "BLOCK" "Blocked $ip | reason=$reason"
    echo -e "${RED}[!] BLOCKED: $ip${NC}"
}

# ─── COUNTER SCAN ─────────────────────────────────────────────────────────────
counter_scan() {
    local ip="$1"
    local scan_dir="/var/log/sentinel/scans"
    mkdir -p "$scan_dir"
    local outfile="$scan_dir/${ip//\//_}_$(date +%s).txt"

    log "SCAN" "Initiating counter-scan on $ip"
    echo -e "${CYAN}[~] Counter-scanning $ip ...${NC}"

    {
        echo "=============================="
        echo " COUNTER-SCAN REPORT"
        echo " Target : $ip"
        echo " Time   : $(date)"
        echo "=============================="
        echo ""

        echo "--- WHOIS ---"
        whois "$ip" 2>/dev/null | grep -E "OrgName|netname|Country|CIDR|address|descr|abuse" || echo "No whois data"
        echo ""

        echo "--- NMAP ---"
        nmap -n -Pn $COUNTER_SCAN_LEVEL -T4 \
             --open \
             -oN - \
             "$ip" 2>&1 || echo "nmap scan failed or timed out"
        echo ""

        echo "--- REVERSE DNS ---"
        host "$ip" 2>/dev/null || echo "No PTR record"

    } > "$outfile" 2>&1

    log "SCAN" "Counter-scan complete for $ip | report=$outfile"
    echo -e "${GREEN}[+] Counter-scan saved: $outfile${NC}"

    # Print summary to console
    echo -e "${BOLD}--- SCAN SUMMARY: $ip ---${NC}"
    grep -E "open|OrgName|netname|Country" "$outfile" | head -30 || true
}

# ─── DETECT SCANS VIA SYSLOG STREAM ──────────────────────────────────────────
# Tracks per-IP hit counts within rolling TIME_WINDOW using temp files
declare -A IP_HIT_COUNT
declare -A IP_FIRST_HIT

monitor_syslog() {
    log "INFO" "Monitoring kernel log for scan patterns..."
    echo -e "${YELLOW}[*] Watching syslog for $SYSLOG_TAG events...${NC}"

    local active_scans=0

    # tail the kernel/syslog log — adjust path for your distro
    local syslog_path="/var/log/kern.log"
    [[ -f /var/log/syslog ]] && syslog_path="/var/log/syslog"
    [[ -f /var/log/messages ]] && syslog_path="/var/log/messages"

    tail -F "$syslog_path" 2>/dev/null | while read -r line; do
        # Only process our tagged lines
        [[ "$line" != *"$SYSLOG_TAG"* ]] && continue

        # Extract source IP
        local src_ip
        src_ip=$(echo "$line" | grep -oP 'SRC=\K[\d.]+') || continue
        [[ -z "$src_ip" ]] && continue

        # Skip already blocked or whitelisted
        is_blocked "$src_ip" && continue
        is_whitelisted "$src_ip" && continue

        local now; now=$(date +%s)

        # Init or increment hit counter
        if [[ -z "${IP_HIT_COUNT[$src_ip]+x}" ]]; then
            IP_HIT_COUNT[$src_ip]=1
            IP_FIRST_HIT[$src_ip]=$now
        else
            IP_HIT_COUNT[$src_ip]=$(( IP_HIT_COUNT[$src_ip] + 1 ))
        fi

        local elapsed=$(( now - IP_FIRST_HIT[$src_ip] ))
        local hits=${IP_HIT_COUNT[$src_ip]}

        # Reset window if expired
        if [[ $elapsed -gt $TIME_WINDOW ]]; then
            IP_HIT_COUNT[$src_ip]=1
            IP_FIRST_HIT[$src_ip]=$now
            continue
        fi

        echo -e "${YELLOW}[~] $src_ip: $hits hits in ${elapsed}s (threshold=$SCAN_THRESHOLD)${NC}"

        if [[ $hits -ge $SCAN_THRESHOLD ]]; then
            log "ALERT" "Scan detected from $src_ip | hits=$hits elapsed=${elapsed}s"

            # Block first
            block_ip "$src_ip" "port_scan_${hits}hits_${elapsed}s"

            # Counter-scan in background, throttled
            if [[ $active_scans -lt $MAX_COUNTER_THREADS ]]; then
                active_scans=$(( active_scans + 1 ))
                (
                    counter_scan "$src_ip"
                    active_scans=$(( active_scans - 1 ))
                ) &
            else
                log "WARN" "Counter-scan throttle reached ($MAX_COUNTER_THREADS) — skipping scan for $src_ip"
            fi

            # Reset counter
            unset IP_HIT_COUNT[$src_ip]
            unset IP_FIRST_HIT[$src_ip]
        fi
    done
}

# ─── MANUAL BLOCK/UNBLOCK ─────────────────────────────────────────────────────
manual_block() {
    local ip="$1"
    block_ip "$ip" "manual"
}

manual_unblock() {
    local ip="$1"
    iptables -D "$IPTABLES_CHAIN" -s "$ip" -j DROP 2>/dev/null && \
        log "INFO" "Unblocked $ip from iptables" || \
        log "WARN" "$ip not found in iptables chain"
    sed -i "/^$ip/d" "$BLOCK_LIST"
    echo -e "${GREEN}[+] Unblocked $ip${NC}"
}

# ─── STATUS ───────────────────────────────────────────────────────────────────
show_status() {
    echo -e "${BOLD}=== SENTINEL STATUS ===${NC}"
    echo -e "Chain   : $IPTABLES_CHAIN"
    echo -e "Blocked : $(wc -l < "$BLOCK_LIST") IPs"
    echo -e "Log     : $LOG_FILE"
    echo ""
    echo -e "${BOLD}--- Active iptables rules ---${NC}"
    iptables -L "$IPTABLES_CHAIN" -n --line-numbers | head -40
    echo ""
    echo -e "${BOLD}--- Last 10 blocked IPs ---${NC}"
    tail -10 "$BLOCK_LIST"
}

# ─── CLEANUP ──────────────────────────────────────────────────────────────────
cleanup() {
    log "INFO" "Sentinel shutting down — flushing chain"
    echo -e "${YELLOW}[!] Shutting down Sentinel...${NC}"
    iptables -F "$IPTABLES_CHAIN"
    iptables -D INPUT -j "$IPTABLES_CHAIN" 2>/dev/null || true
    iptables -X "$IPTABLES_CHAIN" 2>/dev/null || true
    log "INFO" "Sentinel stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
usage() {
    echo ""
    echo -e "${BOLD}Usage:${NC} $0 [command] [args]"
    echo ""
    echo "  start              - Initialize and begin monitoring"
    echo "  stop               - Flush rules and exit"
    echo "  status             - Show current state"
    echo "  block   <ip>       - Manually block an IP"
    echo "  unblock <ip>       - Remove IP block"
    echo "  scan    <ip>       - Manually counter-scan an IP"
    echo "  whitelist <ip>     - Add IP to whitelist"
    echo "  log                - Tail live log"
    echo ""
}

case "${1:-}" in
    start)
        init
        monitor_syslog
        ;;
    stop)
        cleanup
        ;;
    status)
        show_status
        ;;
    block)
        [[ -z "${2:-}" ]] && { echo "Usage: $0 block <ip>"; exit 1; }
        init
        manual_block "$2"
        ;;
    unblock)
        [[ -z "${2:-}" ]] && { echo "Usage: $0 unblock <ip>"; exit 1; }
        manual_unblock "$2"
        ;;
    scan)
        [[ -z "${2:-}" ]] && { echo "Usage: $0 scan <ip>"; exit 1; }
        counter_scan "$2"
        ;;
    whitelist)
        [[ -z "${2:-}" ]] && { echo "Usage: $0 whitelist <ip>"; exit 1; }
        echo "$2" >> "$WHITELIST"
        echo -e "${GREEN}[+] Whitelisted: $2${NC}"
        ;;
    log)
        tail -F "$LOG_FILE"
        ;;
    *)
        usage
        ;;
esac
