#!/usr/bin/env bash
#
# StyleSmuggler (Sansec 0-Day RCE) Detection & Guided Remediation Helper
# Ref: https://sansec.io/research/stylesmuggler
#      https://sansec.io/research/stylesmuggler-0day#the-chronyd-variant
#      https://github.com/disrex-group/stylesmuggler-mitigation
#
# Detects known Indicators of Compromise (IoCs) for the StyleSmuggler
# Magento/Adobe Commerce 0-day - including the fc-cache/gvfsd-user variants
# and the newer chronyd variant - and, if run interactively, offers to walk
# through the incident-response steps in the correct order.
#
# This script never installs, upgrades, or otherwise modifies the Magento
# application itself. It only inspects the OS/filesystem/logs and, if you
# confirm, cleans up OS-level implant artifacts (cron, processes, files,
# Redis sessions). Nginx/WAF hardening suggestions are only ever written to
# a local file for you to review - never applied to live server config.
#
# Usage: ./stylesmuggler-helper.sh [SHOP_DIR] [LOG_DIR]
#
# If LOG_DIR is not given explicitly, it is auto-detected using the
# MAGENTO_CLOUD_PROJECT environment variable that Adobe Commerce Cloud sets
# automatically (holding the project ID): on Pro Staging/Production nodes,
# webserver logs are aggregated under /var/log/platform/<project-id>, so
# that path is used when it actually exists on disk. Dev environments (and
# on-prem/local systems, or Pro nodes where that path doesn't exist) fall
# back to /var/log.

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SHOP_DIR="${1:-.}"
if [ -n "${2:-}" ]; then
    LOG_DIR="$2"
elif [ -n "${MAGENTO_CLOUD_PROJECT:-}" ] && [ -d "/var/log/platform/${MAGENTO_CLOUD_PROJECT}" ]; then
    LOG_DIR="/var/log/platform/${MAGENTO_CLOUD_PROJECT}"
else
    LOG_DIR="/var/log"
fi

FOUND_ISSUES=0

# Detection state, consumed later by the remediation wizard.
FOUND_FILES=()
CRON_SPOOL_HITS=""
MATCHED_PIDS=""

echo -e "${BLUE}=== Checking system for StyleSmuggler IoCs ===${NC}\n"
if [ -z "${2:-}" ]; then
    if [ -n "${MAGENTO_CLOUD_PROJECT:-}" ] && [ "$LOG_DIR" = "/var/log/platform/${MAGENTO_CLOUD_PROJECT}" ]; then
        echo -e "${BLUE}[*] Detected Adobe Commerce Cloud Pro platform logs (MAGENTO_CLOUD_PROJECT=${MAGENTO_CLOUD_PROJECT}) - using LOG_DIR=$LOG_DIR${NC}\n"
    elif [ -n "${MAGENTO_CLOUD_PROJECT:-}" ]; then
        echo -e "${BLUE}[*] Detected Adobe Commerce Cloud (MAGENTO_CLOUD_PROJECT=${MAGENTO_CLOUD_PROJECT}) but /var/log/platform/${MAGENTO_CLOUD_PROJECT} not found - using LOG_DIR=$LOG_DIR${NC}\n"
    fi
fi

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

# Finds processes whose full command line matches the given regex and
# prints them with user/pid/ppid/args columns. Uses pgrep to find matching
# PIDs first (instead of piping 'ps' into 'grep', which would need a
# 'grep -v grep' workaround to exclude the grep process matching itself).
find_procs() {
    local pattern="$1" pids
    pids=$(pgrep -f "$pattern" 2>/dev/null | paste -sd, - || true)
    [ -n "$pids" ] && ps -o user,pid,ppid,args -p "$pids" 2>/dev/null
    return 0
}

# Classifies a PID whose comm is "chronyd" as legitimate, suspicious, or
# unverifiable, based on its REAL on-disk binary (resolved via
# /proc/<pid>/exe - a kernel-resolved reference to the actual executable
# inode, which - unlike argv[0]/comm - a process cannot spoof).
#
# Deliberately does NOT check against a whitelist of "known" legitimate
# chronyd install paths: the chrony package lands in a different place
# on every distro (/usr/sbin, /usr/lib/chrony, /usr/local/sbin, inside a
# container image, ...), so hard-coding paths is a losing game that either
# misses legitimate installs (false alerts) or, worse, gives an attacker
# a documented safe-list to imitate. Instead this checks the properties a
# dropped copy can't fake:
#   - binary deleted from disk while still running ("(deleted)" suffix),
#     or located under a place the webserver account can write to (/tmp,
#     /var/tmp, /dev/shm, /run/user, any user's home, the web root, or
#     any hidden dot-directory component anywhere in the path) -> "alert"
#   - not owned by root -> "alert" (a real system daemon binary is
#     installed by the package manager as root, never by the unprivileged
#     account an RCE runs as)
#   - otherwise (root-owned, outside those locations) -> "legit"
#   - /proc/<pid>/exe unreadable (no permission - e.g. this script runs
#     unprivileged and the real daemon runs as a different system user)
#     -> "unverified", NOT "alert", so a clean host isn't misreported
# Sets globals CHRONYD_VERDICT (legit|alert|unverified) and
# CHRONYD_EXE_PATH (resolved path, or empty if unverified).
classify_chronyd_pid() {
    local pid="$1" exe_owner
    CHRONYD_EXE_PATH=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
    if [ -z "$CHRONYD_EXE_PATH" ]; then
        CHRONYD_VERDICT="unverified"
        return
    fi
    case "$CHRONYD_EXE_PATH" in
        *"(deleted)"*|/tmp/*|/var/tmp/*|/dev/shm/*|/run/user/*|/home/*|/var/www/*|/srv/*|*/.*/*)
            CHRONYD_VERDICT="alert"
            return
            ;;
    esac
    exe_owner=$(stat -c '%U' "/proc/$pid/exe" 2>/dev/null || true)
    if [ -z "$exe_owner" ]; then
        CHRONYD_VERDICT="unverified"
    elif [ "$exe_owner" != "root" ]; then
        CHRONYD_VERDICT="alert"
    else
        CHRONYD_VERDICT="legit"
    fi
}

# Deletes lines matching a sed pattern in-place. GNU sed's -i takes the
# script directly; BSD/macOS sed's -i requires an explicit (possibly empty)
# backup-suffix argument first, so we detect the flavor via `sed --version`
# (only GNU sed understands that flag).
sed_inplace_delete() {
    local pattern="$1" file="$2"
    if sed --version >/dev/null 2>&1; then
        sudo sed -i "$pattern" "$file"
    else
        sudo sed -i '' "$pattern" "$file"
    fi
}

# ----------------------------------------------------------------------
# 1. Check running processes (kworker masquerading, user-space fc-cache)
# ----------------------------------------------------------------------
info "1. Scanning running processes..."

# Real kworkers run as kernel threads (PPID 2 / kthreadd, UID root).
# The Rust implant runs under the web/user account as [kworker/u:8:0].
SUSPICIOUS_KWORKER=$(find_procs '\[kworker/u:8:0\]')
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
BRACKET_NON_ROOT=$(ps -eo user,pid,ppid,args | tail -n +2 | awk '$4 ~ /^\[/ && $1 != "root" && $0 !~ /<defunct>/' || true)
if [ -n "$BRACKET_NON_ROOT" ]; then
    warn "Process(es) masquerading as kernel threads but NOT running as root:\n$BRACKET_NON_ROOT"
else
    ok "No non-root processes masquerading as kernel threads."
fi

# The fc-cache implant resides at ~/.cache/fontconfig/fc-cache - a different
# path than the legitimate system tool (usually /usr/bin/fc-cache), so we
# match specifically on the implant path instead of the generic name
# 'fc-cache', to avoid false positives from regular font cache runs.
SUSPICIOUS_FCCACHE=$(find_procs '\.cache/fontconfig/fc-cache')
if [ -n "$SUSPICIOUS_FCCACHE" ]; then
    warn "Suspicious fc-cache implant process running:\n$SUSPICIOUS_FCCACHE"
    MATCHED_PIDS="$MATCHED_PIDS $(echo "$SUSPICIOUS_FCCACHE" | awk '{print $2}')"
else
    ok "No rogue fc-cache implant process found."
fi

# gvfsd-user implant variant
SUSPICIOUS_GVFSD=$(find_procs 'gvfsd-user')
if [ -n "$SUSPICIOUS_GVFSD" ]; then
    warn "Suspicious gvfsd-user implant process running:\n$SUSPICIOUS_GVFSD"
    MATCHED_PIDS="$MATCHED_PIDS $(echo "$SUSPICIOUS_GVFSD" | awk '{print $2}')"
else
    ok "No rogue gvfsd-user process found."
fi

# chronyd implant variant - the implant re-drops itself and relaunches
# disguised as "chronyd" (the real NTP daemon name), and the drop
# directory varies per infection (seen as both /tmp/.chrony-<8hex>/ and
# $HOME/.cache/chrony/), so matching on a specific dropper path is a dead
# end. Match on the process NAME alone instead - ANY process named
# chronyd is inspected here - and classify each one with
# classify_chronyd_pid() (see its definition above for the full
# rationale: no hard-coded "known good" path list, since that varies by
# distro/packaging - it's judged on ownership and location instead).
CHRONYD_PIDS=$(pgrep -x chronyd 2>/dev/null | sort -u || true)
if [ -n "$CHRONYD_PIDS" ]; then
    CHRONYD_ALERT_DETAIL=""
    CHRONYD_UNVERIFIED_DETAIL=""
    CHRONYD_LEGIT_COUNT=0
    for pid in $CHRONYD_PIDS; do
        classify_chronyd_pid "$pid"
        line=$(ps -o user,pid,ppid,args -p "$pid" 2>/dev/null | tail -n +2)
        case "$CHRONYD_VERDICT" in
            legit)
                CHRONYD_LEGIT_COUNT=$((CHRONYD_LEGIT_COUNT + 1))
                ;;
            alert)
                [ -n "$line" ] && CHRONYD_ALERT_DETAIL="${CHRONYD_ALERT_DETAIL}${line}  [exe=${CHRONYD_EXE_PATH}]
"
                FOUND_FILES+=("${CHRONYD_EXE_PATH% (deleted)}")
                MATCHED_PIDS="$MATCHED_PIDS $pid"
                ;;
            unverified)
                [ -n "$line" ] && CHRONYD_UNVERIFIED_DETAIL="${CHRONYD_UNVERIFIED_DETAIL}${line}
"
                ;;
        esac
    done
    if [ -n "$CHRONYD_ALERT_DETAIL" ]; then
        warn "chronyd process(es) with a suspicious binary found (matched by process NAME since the implant's drop path varies between infections; judged on ownership/location via /proc/<pid>/exe, not a fixed path list):\n$CHRONYD_ALERT_DETAIL"
    fi
    if [ -n "$CHRONYD_UNVERIFIED_DETAIL" ]; then
        echo -e "${YELLOW}[-] chronyd process(es) found but could not verify their real binary path (/proc/<pid>/exe unreadable without root) - re-run as root/sudo for a definitive check:\n$CHRONYD_UNVERIFIED_DETAIL${NC}"
    fi
    if [ -z "$CHRONYD_ALERT_DETAIL" ] && [ -z "$CHRONYD_UNVERIFIED_DETAIL" ]; then
        ok "chronyd process(es) found but all $CHRONYD_LEGIT_COUNT resolve to a legitimate system binary path."
    fi
else
    ok "No chronyd process found at all (neither legitimate nor implant)."
fi

# ----------------------------------------------------------------------
# 2. Check crontabs for persistence
# ----------------------------------------------------------------------
info "2. Checking Crontabs for persistence..."

# a) Crontab of the calling user (fast, no root needed)
CRON_MATCHES=$( (crontab -l 2>/dev/null; [ -d /etc/cron.d ] && cat /etc/cron.d/* 2>/dev/null) | grep -iE '(gvfsd-user|fontconfig/fc-cache|/tmp/\.kw|/tmp/\.fc|chronyd)' || true )
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
        CRON_SPOOL_HITS=$(grep -rnE 'gvfsd-user|fc-cache|chronyd' /var/spool/cron/crontabs/ 2>/dev/null || true)
    else
        CRON_SPOOL_HITS=$(sudo -n grep -rnE 'gvfsd-user|fc-cache|chronyd' /var/spool/cron/crontabs/ 2>/dev/null || true)
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

echo -e "${YELLOW}[-] Note: the chronyd variant's behavior is inconsistent across infections - Sansec documented one instance with NO cron entry at all (re-parented to PID 1, self-relaunching), but other confirmed infections use a plain cron entry that shells out to a dropped chronyd binary (observed: '/bin/sh -c \$HOME/.cache/chrony/chronyd >/dev/null 2>&1' launched by CRON as the webserver user). So an empty/clean crontab does NOT prove the host is clean, but a 'chronyd'-referencing cron line (now included in the scans above) IS a strong IoC either way. Rely on the process, filesystem and network checks below too.${NC}"

# b) Syslog signature: on hosts where the webserver user (e.g. www-data)
#    lacks permission to write its own crontab, the implant's repeated
#    attempts show up as "crontab[<pid>]: (www-data) AUTH (crontab command
#    not allowed)" entries - often in bulk, revealing the infection timing.
CRON_AUTH_PATTERN='crontab\[[0-9]+\]:.*AUTH \(crontab command not allowed\)'
CRON_AUTH_HITS=""
for syslog_file in /var/log/syslog /var/log/cron /var/log/auth.log; do
    if [ -r "$syslog_file" ]; then
        HITS=$(grep -aE "$CRON_AUTH_PATTERN" "$syslog_file" 2>/dev/null || true)
        [ -n "$HITS" ] && CRON_AUTH_HITS="${CRON_AUTH_HITS}${HITS}
"
    fi
done
if command -v journalctl &>/dev/null; then
    HITS=$(journalctl -u cron --no-pager 2>/dev/null | grep -aE "$CRON_AUTH_PATTERN" || true)
    [ -n "$HITS" ] && CRON_AUTH_HITS="${CRON_AUTH_HITS}${HITS}
"
fi
if [ -n "$CRON_AUTH_HITS" ]; then
    warn "Repeated cron AUTH-denied entries found (implant retrying crontab writes as an unprivileged user - reveals infection timing):\n$CRON_AUTH_HITS"
else
    ok "No 'crontab command not allowed' AUTH-denied signature found in syslog/journal."
fi

# ----------------------------------------------------------------------
# 3. Check filesystem for implants and dropper paths
# ----------------------------------------------------------------------
info "3. Checking filesystem artifacts..."

# "/tmp/.chrony-*" and "$HOME/.cache/chrony/chronyd" below are only the
# dropper paths OBSERVED so far - attackers vary this per infection (a
# confirmed real-world hit used $HOME/.cache/chrony/chronyd, not the
# /tmp/.chrony-<8hex>/ path from the original report), so these are kept
# here as known samples but the process-name check in step 1 (which
# resolves the actual /proc/<pid>/exe path at runtime) is the
# authoritative check for the chronyd variant, not this static glob.
SUSPICIOUS_PATHS=(
    "$HOME/.local/share/.gvfsd"
    "$HOME/.cache/fontconfig/fc-cache"
    "$HOME/.cache/chrony/chronyd"
    "/tmp/.fc-*"
    "/tmp/fc-cache"
    "/tmp/.kw_*"
    "/tmp/.cache_*"
    "/tmp/.gvfsd-*"
    "/tmp/.fc_*.lock"
    "/tmp/.chrony-*"
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

# The chronyd-variant report also documents a web shell dropped directly
# inside the shop's own product-image cache directory, disguised as a
# regular cache file: pub/media/catalog/product/cache/ss_<10hex>/sync_<10hex>.php
WEBSHELL_HITS=()
for f in "$SHOP_DIR"/pub/media/catalog/product/cache/ss_*/sync_*.php; do
    [ -e "$f" ] && WEBSHELL_HITS+=("$f")
done
if [ ${#WEBSHELL_HITS[@]} -gt 0 ]; then
    warn "Web shell(s) found in product image cache (ss_*/sync_*.php pattern):"
    for f in "${WEBSHELL_HITS[@]}"; do
        echo -e "    ${RED}- $f${NC}"
        FOUND_FILES+=("$f")
    done
else
    ok "No ss_*/sync_*.php web shell pattern found in pub/media/catalog/product/cache."
fi

# ----------------------------------------------------------------------
# 5. Active network sockets / C2 connections
# ----------------------------------------------------------------------
info "5. Checking active network sockets..."

C2_IPS="99.84.67.186|209.141.43.95|88.216.72.181|182.182.152.48|76.31.99.207|209.73.130.148|77.239.124.107|185.157.160.251"
if command -v ss &>/dev/null; then
    SOCKET_HITS=$(ss -tupn 2>/dev/null | grep -E "$C2_IPS" || true)
elif command -v netstat &>/dev/null; then
    # -an (all sockets, numeric) is the common denominator between GNU and
    # BSD/macOS netstat - GNU's -tupn combo isn't understood by BSD netstat.
    SOCKET_HITS=$(netstat -an 2>/dev/null | grep -E "$C2_IPS" || true)
else
    SOCKET_HITS=""
fi

if [ -n "$SOCKET_HITS" ]; then
    warn "Active network connection to known C2 IP found:\n$SOCKET_HITS"
else
    ok "No active sockets to known C2 IPs."
fi
echo -e "${YELLOW}[-] Note: the report also lists C2 domains (247.cdnflare.xyz, windwsecurity.run, ntp.timesync.to, ntp.synctime.to, ntp.syncstime.to, ntp.timesysnc.net, time.microsft.run, pool.microsft.studio) tunneled over NTP/UDP 123 - these are not resolvable from socket state alone; check DNS resolver logs if available.${NC}"
echo -e "${YELLOW}[-] Note: the chronyd variant's C2 traffic has a distinctive shape even without DNS logs - it sends NTPv4 packets in 'server' mode (legitimate NTP clients never do this) as nine 48-byte datagrams roughly 10ms apart, repeating every 60 seconds, over UDP/123. To inspect manually: sudo tcpdump -ni any udp port 123 -c 100 -w ntp_check.pcap${NC}"

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
    if confirm "Remove the matching gvfsd-user/fc-cache/chronyd lines from the file(s) above? (uses sudo sed -i)"; then
        while IFS= read -r cf; do
            [ -n "$cf" ] || continue
            if sed_inplace_delete '/gvfsd-user/d;/fc-cache/d;/chronyd/d' "$cf"; then
                ok "Cleaned $cf"
            else
                echo -e "${RED}[!] Failed to clean $cf - remove the malicious line(s) manually.${NC}"
            fi
        done <<< "$CRON_FILES"
    fi
elif [ -n "${CRON_MATCHES:-}" ]; then
    echo "Suspicious entries were found in the CURRENT user's crontab."
    if confirm "Remove matching lines from your own crontab now? (crontab -l | grep -v ... | crontab -)"; then
        crontab -l 2>/dev/null | grep -viE '(gvfsd-user|fontconfig/fc-cache|/tmp/\.kw|/tmp/\.fc|chronyd)' | crontab -
        ok "Crontab cleaned for current user."
    fi
else
    ok "No cron persistence to remove."
fi

# --- Step 3: kill malicious processes ----------------------------------
echo -e "\n${BLUE}${BOLD}[Step 3/6] Terminate malicious processes${NC}"
# chronyd is matched by name (-x), not by dropper path, since that path
# varies between infections - see classify_chronyd_pid() and the
# detection step above. Unlike the other implants, "chronyd" is also a
# real system service name, so this blanket SIGKILL step must NOT
# include a PID just because it's named chronyd: only PIDs classified
# "alert" (suspicious ownership/location) are included. A "legit" or
# "unverified" verdict is excluded here - never auto-killed, even after
# confirmation, since the confirm prompt below only shows bare PIDs with
# no path context.
CHRONYD_KILL_PIDS=""
for pid in $(pgrep -x chronyd 2>/dev/null || true); do
    classify_chronyd_pid "$pid"
    [ "$CHRONYD_VERDICT" = "alert" ] && CHRONYD_KILL_PIDS="$CHRONYD_KILL_PIDS $pid"
done
LIVE_PIDS=$( { pgrep -f 'gvfsd-user|\.cache/fontconfig/fc-cache|\[kworker/u:8:0\]'; echo "$CHRONYD_KILL_PIDS"; } 2>/dev/null | tr ' ' '\n' | grep -v '^$' | sort -u || true)
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
