#!/usr/bin/env bash
#
# StyleSmuggler (Sansec 0-Day RCE) Detection & Guided Remediation Helper
# Ref: https://sansec.io/research/stylesmuggler
#
# Detects known Indicators of Compromise (IoCs) for the StyleSmuggler
# Magento/Adobe Commerce 0-day, and - if run interactively - offers to walk
# through the incident-response steps in the correct order.
#
# This script never installs, upgrades, or otherwise modifies the Magento
# application itself. It only inspects the OS/filesystem/logs and, if you
# confirm, cleans up OS-level implant artifacts (cron, processes, files,
# Redis sessions). Nginx/WAF hardening suggestions are only ever written to
# a local file for you to review - never applied to live server config.
#
# Usage: ./stylesmuggler-helper.sh [SHOP_DIR] [LOG_DIR]

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SHOP_DIR="${1:-.}"
LOG_DIR="${2:-/var/log}"

FOUND_ISSUES=0

# Detection state, consumed later by the remediation wizard.
FOUND_FILES=()
CRON_SPOOL_HITS=""
MATCHED_PIDS=""

echo -e "${BLUE}=== Checking system for StyleSmuggler IoCs ===${NC}\n"

warn() {
    echo -e "${RED}[ALERT] $1${NC}"
    FOUND_ISSUES=$((FOUND_ISSUES + 1))
}

ok() {
    echo -e "${GREEN}[OK] $1${NC}"
}

info() {
    echo -e "${BLUE}[*] $1${NC}"
}

confirm() {
    local reply
    read -r -p "$(echo -e "${YELLOW}$1 [y/N]: ${NC}")" reply
    case "$reply" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# ----------------------------------------------------------------------
# 1. Check running processes (kworker masquerading, user-space fc-cache)
# ----------------------------------------------------------------------
info "1. Scanning running processes..."

# Real kworkers run as kernel threads (PPID 2 / kthreadd, UID root).
# The Rust implant runs under the web/user account as [kworker/u:8:0].
SUSPICIOUS_KWORKER=$(ps -eo user,pid,ppid,args | grep -E '\[kworker/u:8:0\]' | grep -v grep || true)
if [ -n "$SUSPICIOUS_KWORKER" ]; then
    warn "Suspicious kworker process found running in user space:\n$SUSPICIOUS_KWORKER"
    MATCHED_PIDS="$MATCHED_PIDS $(echo "$SUSPICIOUS_KWORKER" | awk '{print $2}')"
else
    ok "No rogue [kworker/u:8:0] process found."
fi

# Additional, broader heuristic: ANY process that masquerades as a kernel
# thread via square brackets but does NOT run as root is by definition not
# a real kernel thread (real kernel threads always run as root).
# Zombie/<defunct> processes are also shown by ps in square brackets,
# regardless of the original program - this is a normal, harmless Linux
# phenomenon and is therefore explicitly excluded.
BRACKET_NON_ROOT=$(ps -eo user,pid,ppid,args --no-headers | awk '$4 ~ /^\[/ && $1 != "root" && $0 !~ /<defunct>/' || true)
if [ -n "$BRACKET_NON_ROOT" ]; then
    warn "Process(es) masquerading as kernel threads but NOT running as root:\n$BRACKET_NON_ROOT"
else
    ok "No non-root processes masquerading as kernel threads."
fi

# The fc-cache implant resides at ~/.cache/fontconfig/fc-cache - a different
# path than the legitimate system tool (usually /usr/bin/fc-cache), so we
# match specifically on the implant path instead of the generic name
# 'fc-cache', to avoid false positives from regular font cache runs.
SUSPICIOUS_FCCACHE=$(ps -eo user,pid,ppid,args | grep -E '\.cache/fontconfig/fc-cache' | grep -v grep || true)
if [ -n "$SUSPICIOUS_FCCACHE" ]; then
    warn "Suspicious fc-cache implant process running:\n$SUSPICIOUS_FCCACHE"
    MATCHED_PIDS="$MATCHED_PIDS $(echo "$SUSPICIOUS_FCCACHE" | awk '{print $2}')"
else
    ok "No rogue fc-cache implant process found."
fi

# gvfsd-user implant variant
SUSPICIOUS_GVFSD=$(ps -eo user,pid,ppid,args | grep -E 'gvfsd-user' | grep -v grep || true)
if [ -n "$SUSPICIOUS_GVFSD" ]; then
    warn "Suspicious gvfsd-user implant process running:\n$SUSPICIOUS_GVFSD"
    MATCHED_PIDS="$MATCHED_PIDS $(echo "$SUSPICIOUS_GVFSD" | awk '{print $2}')"
else
    ok "No rogue gvfsd-user process found."
fi

# ----------------------------------------------------------------------
# 2. Check crontabs for persistence
# ----------------------------------------------------------------------
info "2. Checking Crontabs for persistence..."

# a) Crontab of the calling user (fast, no root needed)
CRON_MATCHES=$( (crontab -l 2>/dev/null; [ -d /etc/cron.d ] && cat /etc/cron.d/* 2>/dev/null) | grep -iE '(gvfsd-user|fontconfig/fc-cache|/tmp/\.kw|/tmp/\.fc)' || true )
if [ -n "$CRON_MATCHES" ]; then
    warn "Suspicious cronjob detected in current user's crontab / cron.d:\n$CRON_MATCHES"
else
    ok "Current user's crontab and /etc/cron.d clean."
fi

# b) Direct scan of the cron spool files of ALL users. According to the
#    report, the implant writes directly into /var/spool/cron/crontabs/<user>,
#    bypassing the calling user's 'crontab -l' if the webserver runs under a
#    different account (e.g. www-data). This usually requires root/sudo.
if [ -d /var/spool/cron/crontabs ]; then
    if [ "$(id -u)" -eq 0 ]; then
        CRON_SPOOL_HITS=$(grep -rnE 'gvfsd-user|fc-cache' /var/spool/cron/crontabs/ 2>/dev/null || true)
    else
        CRON_SPOOL_HITS=$(sudo -n grep -rnE 'gvfsd-user|fc-cache' /var/spool/cron/crontabs/ 2>/dev/null || true)
    fi

    if [ -n "$CRON_SPOOL_HITS" ]; then
        warn "Suspicious entry found directly in cron spool files (may belong to a DIFFERENT user than the one running this script):\n$CRON_SPOOL_HITS"
    elif [ "$(id -u)" -ne 0 ]; then
        echo -e "${YELLOW}[-] Could not read /var/spool/cron/crontabs/ without root - re-run as root/sudo to check OTHER users' crontabs (e.g. the webserver user).${NC}"
    else
        ok "Cron spool directory clean (all users)."
    fi
else
    echo -e "${YELLOW}[-] /var/spool/cron/crontabs not found on this system (different cron implementation?) - check manually.${NC}"
fi

# ----------------------------------------------------------------------
# 3. Check filesystem for implants and dropper paths
# ----------------------------------------------------------------------
info "3. Checking filesystem artifacts..."

SUSPICIOUS_PATHS=(
    "$HOME/.local/share/.gvfsd"
    "$HOME/.cache/fontconfig/fc-cache"
    "/tmp/.fc-*"
    "/tmp/fc-cache"
    "/tmp/.kw_*"
    "/tmp/.cache_*"
    "/tmp/.gvfsd-*"
    "/tmp/.fc_*.lock"
)

for pattern in "${SUSPICIOUS_PATHS[@]}"; do
    for file in $pattern; do
        if [ -e "$file" ]; then
            FOUND_FILES+=("$file")
        fi
    done
done

if [ ${#FOUND_FILES[@]} -gt 0 ]; then
    warn "Suspicious files/directories discovered:"
    for f in "${FOUND_FILES[@]}"; do
        echo -e "    ${RED}- $f${NC}"
    done
else
    ok "No dropper/implant files detected in /tmp or user home."
fi

# ----------------------------------------------------------------------
# 4. Magento var/report / var/log Poisoning
# ----------------------------------------------------------------------
info "4. Checking Magento var/report and var/log for payload traces..."

POISON_HITS=""
if [ -d "$SHOP_DIR/var/report" ] || [ -f "$SHOP_DIR/var/log/system.log" ]; then
    POISON_HITS=$(grep -rlE 'eval\(base64_decode' "$SHOP_DIR/var/report/" "$SHOP_DIR/var/log/" 2>/dev/null || true)
    if [ -n "$POISON_HITS" ]; then
        warn "Poisoned payload fragments ('eval(base64_decode') found:\n$POISON_HITS"
    else
        ok "var/report/ and var/log/ clean (no 'eval(base64_decode' injections found)."
    fi

    SYSTEM_LOG_ERR=$(grep -E 'TypeError.*array_merge' "$SHOP_DIR/var/log/system.log" 2>/dev/null | head -n 5 || true)
    if [ -n "$SYSTEM_LOG_ERR" ]; then
        warn "TypeError involving array_merge() found in system.log (possible exploit attempt):\n$SYSTEM_LOG_ERR"
    else
        ok "No array_merge() TypeError signature in system.log."
    fi
else
    echo -e "${YELLOW}[-] Neither '$SHOP_DIR/var/report' nor '$SHOP_DIR/var/log/system.log' found. Specify shop root as arg 1: $0 /path/to/magento${NC}"
fi

# ----------------------------------------------------------------------
# 5. Active network sockets / C2 connections
# ----------------------------------------------------------------------
info "5. Checking active network sockets..."

C2_IPS="99.84.67.186|209.141.43.95|88.216.72.181"
if command -v ss &>/dev/null; then
    SOCKET_HITS=$(ss -tupn 2>/dev/null | grep -E "$C2_IPS" || true)
elif command -v netstat &>/dev/null; then
    SOCKET_HITS=$(netstat -tupn 2>/dev/null | grep -E "$C2_IPS" || true)
else
    SOCKET_HITS=""
fi

if [ -n "$SOCKET_HITS" ]; then
    warn "Active network connection to known C2 IP found:\n$SOCKET_HITS"
else
    ok "No active sockets to known C2 IPs."
fi
echo -e "${YELLOW}[-] Note: the report also lists C2 domains (247.cdnflare.xyz, windwsecurity.run, ntp.timesync.to, ntp.synctime.to, ntp.timesysnc.net, time.microsft.run) tunneled over NTP/UDP 123 - these are not resolvable from socket state alone; check DNS resolver logs if available.${NC}"

# ----------------------------------------------------------------------
# 6. Webserver-Log Search
# ----------------------------------------------------------------------
info "6. Checking Web Access Logs for exploitation patterns..."

if [ -d "$LOG_DIR" ] || [ -f "$LOG_DIR" ]; then
    # -r makes the search work regardless of whether LOG_DIR is a single file
    # or a directory (e.g. /var/log) - without -r, grep would abort on a
    # directory with "Is a directory" and SILENTLY return no matches.
    LOG_HITS=$(grep -rE '(styles(\[|%5B)|generatorClass|with_resolved|eval\(base64_decode|/paypal/transparent/response/\?<\?|209\.141\.43\.95|88\.216\.72\.181|247\.cdnflare\.xyz|windwsecurity\.run)' "$LOG_DIR" 2>/dev/null | head -n 10 || true)
    if [ -n "$LOG_HITS" ]; then
        warn "Suspicious requests found in access logs (showing first hits):\n$LOG_HITS"
    else
        ok "No obvious StyleSmuggler attack signatures found in $LOG_DIR (sample)."
    fi
else
    echo -e "${YELLOW}[-] Log path '$LOG_DIR' not found. Specify log directory as arg 2.${NC}"
fi

# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------
echo ""
if [ $FOUND_ISSUES -eq 0 ]; then
    echo -e "${GREEN}=== RESULT: System appears CLEAN of StyleSmuggler IoCs ===${NC}"
    exit 0
fi

echo -e "${RED}=== RESULT: $FOUND_ISSUES POSSIBLE IOC(s) DETECTED! Immediate manual inspection required. ===${NC}"

echo -e "\n${RED}${BOLD}================================================================${NC}"
echo -e "${RED}${BOLD}                    NO WARRANTY - USE AT OWN RISK               ${NC}"
echo -e "${RED}${BOLD}================================================================${NC}"
echo -e "${RED}${BOLD}This script is provided AS IS, WITHOUT WARRANTY OF ANY KIND,${NC}"
echo -e "${RED}${BOLD}express or implied. ALL cleanup/remediation steps below are${NC}"
echo -e "${RED}${BOLD}performed ENTIRELY AT YOUR OWN RISK.${NC}"
echo -e "${RED}${BOLD}The author(s) accept NO LIABILITY whatsoever for data loss,${NC}"
echo -e "${RED}${BOLD}downtime, broken systems, or any other damage resulting from${NC}"
echo -e "${RED}${BOLD}running this script or acting on its output.${NC}"
echo -e "${RED}${BOLD}Every action below that changes system state WILL ask for your${NC}"
echo -e "${RED}${BOLD}explicit y/N confirmation first - read each prompt carefully${NC}"
echo -e "${RED}${BOLD}and verify the outcome yourself.${NC}"
echo -e "${RED}${BOLD}================================================================${NC}"

# ----------------------------------------------------------------------
# Guided remediation (interactive only)
# ----------------------------------------------------------------------
if [ ! -t 0 ]; then
    echo -e "\n${YELLOW}Re-run this script in an interactive terminal (not piped/cron) to get a guided, step-by-step cleanup.${NC}"
    exit 1
fi

echo ""
if ! confirm "Start guided remediation now?"; then
    echo "Skipping remediation. Re-run the script any time to start it."
    exit 1
fi

echo -e "\n${BOLD}${RED}IMPORTANT: follow the steps in order.${NC}"
echo -e "${RED}Do NOT kill processes before cron cleanup, and do NOT reboot the server -${NC}"
echo -e "${RED}the implant restores its cron entry within seconds and a reboot destroys${NC}"
echo -e "${RED}volatile evidence in memory.${NC}"

# --- Step 1: forensic preservation reminder ---------------------------
echo -e "\n${BLUE}${BOLD}[Step 1/6] Forensic preservation${NC}"
echo "Before changing anything, consider preserving (copies, not on this host if possible):"
echo "  - Output of: ps -ef ; ss -tupn"
echo "  - /proc/<pid>/ of the suspicious processes found above"
echo "  - Copies of var/log/ and var/report/ and the cron spool files"
if ! confirm "Have you preserved the evidence you need and are you ready to continue?"; then
    echo "Stopping here. Re-run this script when you're ready to proceed with cleanup."
    exit 1
fi

# --- Step 2: remove cron persistence (BEFORE killing processes) -------
echo -e "\n${BLUE}${BOLD}[Step 2/6] Remove cron persistence${NC}"
if [ -n "$CRON_SPOOL_HITS" ]; then
    echo "$CRON_SPOOL_HITS"
    CRON_FILES=$(printf '%s\n' "$CRON_SPOOL_HITS" | cut -d: -f1 | sort -u)
    if confirm "Remove the matching gvfsd-user/fc-cache lines from the file(s) above? (uses sudo sed -i)"; then
        while IFS= read -r cf; do
            [ -n "$cf" ] || continue
            if sudo sed -i '/gvfsd-user/d;/fc-cache/d' "$cf"; then
                ok "Cleaned $cf"
            else
                echo -e "${RED}[!] Failed to clean $cf - remove the malicious line(s) manually.${NC}"
            fi
        done <<< "$CRON_FILES"
    fi
elif [ -n "${CRON_MATCHES:-}" ]; then
    echo "Suspicious entries were found in the CURRENT user's crontab."
    if confirm "Remove matching lines from your own crontab now? (crontab -l | grep -v ... | crontab -)"; then
        crontab -l 2>/dev/null | grep -viE '(gvfsd-user|fontconfig/fc-cache|/tmp/\.kw|/tmp/\.fc)' | crontab -
        ok "Crontab cleaned for current user."
    fi
else
    ok "No cron persistence to remove."
fi

# --- Step 3: kill malicious processes ----------------------------------
echo -e "\n${BLUE}${BOLD}[Step 3/6] Terminate malicious processes${NC}"
LIVE_PIDS=$(ps -eo pid,args | grep -E 'gvfsd-user|\.cache/fontconfig/fc-cache|\[kworker/u:8:0\]' | grep -v grep | awk '{print $1}' | sort -u || true)
if [ -n "$LIVE_PIDS" ]; then
    echo "Matching PID(s): $LIVE_PIDS"
    if confirm "Send SIGKILL to these PID(s)?"; then
        for pid in $LIVE_PIDS; do
            if sudo kill -9 "$pid" 2>/dev/null; then
                ok "Killed PID $pid"
            else
                echo -e "${RED}[!] Could not kill PID $pid - it may have already exited or need different privileges.${NC}"
            fi
        done
    fi
else
    ok "No matching processes currently running."
fi

# --- Step 4: quarantine implant files -----------------------------------
echo -e "\n${BLUE}${BOLD}[Step 4/6] Quarantine implant files${NC}"
if [ ${#FOUND_FILES[@]} -gt 0 ]; then
    if [ "$(id -u)" -eq 0 ]; then
        QUARANTINE_DIR="${QUARANTINE_DIR:-/root/quarantine_stylesmuggler_$(date +%Y%m%d%H%M%S)}"
    else
        QUARANTINE_DIR="${QUARANTINE_DIR:-$HOME/quarantine_stylesmuggler_$(date +%Y%m%d%H%M%S)}"
    fi
    echo "Files to quarantine:"
    for f in "${FOUND_FILES[@]}"; do echo "  - $f"; done
    if confirm "Move these into $QUARANTINE_DIR ?"; then
        mkdir -p "$QUARANTINE_DIR"
        for f in "${FOUND_FILES[@]}"; do
            if sudo mv "$f" "$QUARANTINE_DIR/" 2>/dev/null; then
                ok "Quarantined $f"
            else
                echo -e "${RED}[!] Could not move $f - remove/quarantine it manually.${NC}"
            fi
        done
    fi
else
    ok "No implant files to quarantine."
fi

# --- Step 5: invalidate Redis sessions ----------------------------------
echo -e "\n${BLUE}${BOLD}[Step 5/6] Invalidate Magento sessions in Redis${NC}"
echo "The implant can read live sessions/auth tokens directly out of Redis memory."
echo -e "${YELLOW}Flushing a Redis DB logs out every real user on that database too.${NC}"
if command -v redis-cli &>/dev/null; then
    if confirm "Flush a Redis session database now?"; then
        read -r -p "Redis session DB index (see 'session' cache_backend in app/etc/env.php): " db_index
        if [[ "$db_index" =~ ^[0-9]+$ ]]; then
            if redis-cli -n "$db_index" FLUSHDB; then
                ok "Flushed Redis DB $db_index"
            else
                echo -e "${RED}[!] redis-cli FLUSHDB failed - check connection/auth and run manually.${NC}"
            fi
        else
            echo -e "${RED}[!] Invalid DB index, skipped. Run manually: redis-cli -n <index> FLUSHDB${NC}"
        fi
    fi
else
    echo -e "${YELLOW}[-] redis-cli not found on this host - flush sessions manually from wherever Redis is reachable.${NC}"
fi

# --- Step 6: credential rotation checklist (manual, not automated) -----
echo -e "\n${BLUE}${BOLD}[Step 6/6] Credential rotation (manual - not automated by this script)${NC}"
cat <<'EOF'
Rotate the following now - this script does NOT do this for you:
  - Database credentials
  - app/etc/env.php crypt key
  - All Magento admin user accounts
  - API / integration tokens
  - Payment provider API keys
  - SSH keys of the system user running the webserver
EOF

# --- Optional: infra hardening suggestions (written to file, never applied) ---
echo -e "\n${BLUE}${BOLD}[Optional] Write infrastructure hardening suggestions to a file${NC}"
echo "This only ever writes a local reference file for you to review and apply"
echo "yourself to your webserver/PHP config - it never touches Magento or live"
echo "server configuration."
if confirm "Write nginx/WAF/php.ini hardening suggestions to ./stylesmuggler-hardening.txt ?"; then
    cat > ./stylesmuggler-hardening.txt <<'EOF'
StyleSmuggler - infrastructure hardening suggestions (review before applying)
==============================================================================
These are perimeter/OS mitigations only. They do not patch the underlying
DI-compiler object-injection issue and do not modify Magento itself. Watch
Adobe's security bulletins for the official patch.

1) Cloudflare WAF rule:
(http.request.uri.path contains "/graphql" and (http.request.uri.query contains "styles%5B" or http.request.uri.query contains "styles[")) or (http.request.uri.query contains "generatorClass" or http.request.uri.query contains "with_resolved") or (http.request.uri.query contains "eval(base64_decode")

2) Nginx query-string filter (note: only inspects the query string, not
   POST body/JSON payloads - defense in depth only, not a complete block):
if ($query_string ~* "(styles(\[|%5B)|generatorClass|with_resolved|eval\(base64_decode)") {
    return 403;
}

3) If this shop uses a classic (Luma/Hyva) storefront with no headless/PWA
   frontend, consider disabling the GraphQL endpoint entirely at the
   webserver level:
location /graphql {
    return 403;
}

4) php.ini - lock down process execution functions (watch out for
   proc_open specifically, observed droppers fall back to it when
   exec/system are blocked):
disable_functions = exec, passthru, shell_exec, system, proc_open, popen

5) Mount /tmp, /var/tmp, /dev/shm with the 'noexec' option to prevent
   downloaded ELF binaries from executing.
EOF
    ok "Wrote ./stylesmuggler-hardening.txt"
fi

echo -e "\n${GREEN}Guided remediation finished. Keep monitoring - re-run this script periodically.${NC}"
