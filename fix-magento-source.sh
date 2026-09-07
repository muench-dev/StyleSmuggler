#!/usr/bin/env bash
#
# StyleSmuggler (Sansec 0-Day RCE) Proactive Hardening / Fix Helper
# Ref: https://sansec.io/research/stylesmuggler
# Ref: https://github.com/disrex-group/stylesmuggler-mitigation
#
# Applies the community mitigations for the StyleSmuggler Magento/Adobe
# Commerce 0-day while no official Adobe patch exists yet:
#
#   1. Installs and enables the graycoreio/magento2-style-smuggler-patch
#      Composer module (executed against MAGENTO_ROOT, step by step).
#   2. Downloads and applies (via cweagans/composer-patches) the two real
#      source patches published by Disrex for the root cause: the
#      magento/module-email "front door" (email template preview block
#      renders {{block}} directives outside the admin area) and the
#      magento/magento2-base "sink" (3 DI-compiler scanner classes that
#      include/require_once a caller-supplied path), guarded to CLI-only.
#      Fetched from a pinned commit of disrex-group/stylesmuggler-mitigation,
#      never from a moving branch tip - review each downloaded diff before
#      it's wired into composer.json and applied.
#   3. Writes webserver/WAF/php.ini/OS hardening suggestions to a local file
#      for manual review - this script NEVER edits live nginx/php.ini/fstab
#      config or restarts services.
#
# Every state-changing action asks for explicit y/N confirmation first.
#
# Automatically detects ddev and Warden local dev environments and runs
# Composer/bin-magento through them (`ddev composer` / `ddev exec ...`,
# `warden env exec php-fpm ...`) instead of directly on the host. Override
# detection with FIX_MAGENTO_ENV=ddev|warden|native, and the Warden PHP
# service name with WARDEN_PHP_SERVICE (default: php-fpm).
#
# This script does NOT detect or clean up an existing compromise - use
# stylesmuggler-helper.sh for IoC detection and incident-response cleanup.
#
# Usage: ./fix-magento-source.sh [MAGENTO_ROOT]

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

MAGENTO_ROOT="${1:-.}"

warn() {
    echo -e "${RED}[!] $1${NC}"
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

# Detects whether MAGENTO_ROOT is managed by ddev, Warden, or plain/native
# composer+bin/magento on the host. Honors FIX_MAGENTO_ENV=ddev|warden|native
# as an override for ambiguous or misdetected setups.
detect_env() {
    case "${FIX_MAGENTO_ENV:-}" in
        ddev|warden|native) echo "$FIX_MAGENTO_ENV"; return ;;
    esac

    if [ -d "$MAGENTO_ROOT/.ddev" ]; then
        if command -v ddev >/dev/null 2>&1; then
            echo "ddev"
            return
        fi
        warn "Found '$MAGENTO_ROOT/.ddev' but the 'ddev' CLI is not on PATH - falling back to native (composer/bin/magento run on the host)." >&2
    fi

    if grep -q '^WARDEN_ENV_NAME=' "$MAGENTO_ROOT/.env" 2>/dev/null; then
        if command -v warden >/dev/null 2>&1; then
            echo "warden"
            return
        fi
        warn "Found WARDEN_ENV_NAME in '$MAGENTO_ROOT/.env' but the 'warden' CLI is not on PATH - falling back to native (composer/bin/magento run on the host)." >&2
    fi

    echo "native"
}

# Runs Composer / bin/magento inside MAGENTO_ROOT through the detected
# environment (ddev/Warden/native), without ever changing this script's cwd.
run_composer() { (cd "$MAGENTO_ROOT" && "${COMPOSER_CMD[@]}" "$@"); }
run_magento()  { (cd "$MAGENTO_ROOT" && "${MAGENTO_CMD[@]}" "$@"); }

echo -e "${BLUE}${BOLD}=== StyleSmuggler proactive hardening for: $MAGENTO_ROOT ===${NC}\n"

echo -e "${RED}${BOLD}================================================================${NC}"
echo -e "${RED}${BOLD}                    NO WARRANTY - USE AT OWN RISK               ${NC}"
echo -e "${RED}${BOLD}================================================================${NC}"
echo -e "${RED}${BOLD}This script is provided AS IS, WITHOUT WARRANTY OF ANY KIND,${NC}"
echo -e "${RED}${BOLD}express or implied. These are community/best-effort mitigations,${NC}"
echo -e "${RED}${BOLD}NOT an official Adobe patch, and are applied ENTIRELY AT YOUR${NC}"
echo -e "${RED}${BOLD}OWN RISK. Validate on a staging system before production.${NC}"
echo -e "${RED}${BOLD}Every action below that changes state WILL ask for your explicit${NC}"
echo -e "${RED}${BOLD}y/N confirmation first - read each prompt carefully.${NC}"
echo -e "${RED}${BOLD}================================================================${NC}\n"

# ----------------------------------------------------------------------
# Preflight: does MAGENTO_ROOT actually look like a Magento install?
# ----------------------------------------------------------------------
if [ ! -f "$MAGENTO_ROOT/composer.json" ] || [ ! -f "$MAGENTO_ROOT/bin/magento" ]; then
    warn "'$MAGENTO_ROOT' does not look like a Magento/Adobe Commerce root (missing composer.json or bin/magento)."
    echo "Pass the correct path: $0 /path/to/magento"
    exit 1
fi
ok "Found composer.json and bin/magento in '$MAGENTO_ROOT'."

# ----------------------------------------------------------------------
# Detect ddev / Warden / native and build the command prefixes
# ----------------------------------------------------------------------
ENV_MODE=$(detect_env)
case "$ENV_MODE" in
    ddev)
        COMPOSER_CMD=(ddev composer)
        MAGENTO_CMD=(ddev exec bin/magento)
        info "Detected environment: ddev"
        ;;
    warden)
        COMPOSER_CMD=(warden env exec -T "${WARDEN_PHP_SERVICE:-php-fpm}" composer)
        MAGENTO_CMD=(warden env exec -T "${WARDEN_PHP_SERVICE:-php-fpm}" bin/magento)
        info "Detected environment: warden (service: ${WARDEN_PHP_SERVICE:-php-fpm})"
        ;;
    *)
        COMPOSER_CMD=(composer)
        MAGENTO_CMD=(bin/magento)
        info "Detected environment: native (direct composer/bin/magento)"
        ;;
esac

# ----------------------------------------------------------------------
# Step 1: Graycore community patch (executed, confirmed per command)
# ----------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Step 1] Graycore community patch (graycoreio/magento2-style-smuggler-patch)${NC}"
echo "This module: blocks the {{block}} directive in email templates, adds strict"
echo "class validation before instantiation in the grid-row URL generator factory,"
echo "and breaks open PHP tags inside fatal Web API error reports to prevent"
echo "log/report poisoning."

ALREADY_INSTALLED=""
if grep -q '"graycore/magento2-style-smuggler-patch"' "$MAGENTO_ROOT/composer.json" 2>/dev/null; then
    ALREADY_INSTALLED="1"
fi

if [ -n "$ALREADY_INSTALLED" ]; then
    ok "graycore/magento2-style-smuggler-patch already present in composer.json - skipping install."
else
    if confirm "Run: ${COMPOSER_CMD[*]} require graycore/magento2-style-smuggler-patch ?"; then
        if run_composer require graycore/magento2-style-smuggler-patch; then
            ok "Composer package installed."
        else
            warn "composer require failed - inspect the output above before continuing."
            ALREADY_INSTALLED=""
        fi
    else
        echo "Skipped. The remaining Graycore steps below need this package - skipping them too."
    fi
fi

if grep -q '"graycore/magento2-style-smuggler-patch"' "$MAGENTO_ROOT/composer.json" 2>/dev/null; then
    if confirm "Run: ${MAGENTO_CMD[*]} module:enable Graycore_StyleSmugglerPatch ?"; then
        if run_magento module:enable Graycore_StyleSmugglerPatch; then
            ok "Module enabled."

            if confirm "Run: ${MAGENTO_CMD[*]} setup:upgrade ?"; then
                if run_magento setup:upgrade; then
                    ok "setup:upgrade completed."

                    if confirm "Run: ${MAGENTO_CMD[*]} setup:di:compile ?"; then
                        if run_magento setup:di:compile; then
                            ok "setup:di:compile completed."
                        else
                            warn "setup:di:compile failed - inspect the output above."
                        fi
                    else
                        echo "Skipped setup:di:compile - the module is enabled but DI generation is stale until you run it."
                    fi
                else
                    warn "setup:upgrade failed - inspect the output above before running setup:di:compile."
                fi
            else
                echo "Skipped setup:upgrade."
            fi
        else
            warn "module:enable failed - inspect the output above."
        fi
    else
        echo "Skipped module:enable."
    fi
fi

echo -e "${YELLOW}Note: this module is a hardening measure, not a fix for the structural root${NC}"
echo -e "${YELLOW}cause in the DI compiler - alternative object paths remain theoretically${NC}"
echo -e "${YELLOW}possible. It also does NOT remove any backdoor that may already be present${NC}"
echo -e "${YELLOW}(use stylesmuggler-helper.sh for that). Validate on staging first.${NC}"

# ----------------------------------------------------------------------
# Step 2: DI-compiler hardening scaffold (cweagans/composer-patches)
# ----------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Step 2] Disrex source patches: front door + DI-scanner sink${NC}"
echo "Disrex has published two real patches for the root cause (not just the"
echo "Graycore hardening module above):"
echo "  - magento/module-email: the email template preview block (the FRONT DOOR -"
echo "    it renders {{block}} directives from an unauthenticated request; guarding"
echo "    it makes the whole gadget chain unreachable, the stronger of the two)"
echo "  - magento/magento2-base: the 3 DI-compiler scanner classes (the SINK - the"
echo "    include/require_once that ends the chain), guarded to run CLI-only so"
echo "    'bin/magento setup:di:compile' itself keeps working"

if grep -q '"cweagans/composer-patches"' "$MAGENTO_ROOT/composer.json" 2>/dev/null; then
    ok "cweagans/composer-patches already present in composer.json."
else
    if confirm "Run: ${COMPOSER_CMD[*]} require cweagans/composer-patches ?"; then
        if run_composer require cweagans/composer-patches; then
            ok "cweagans/composer-patches installed."
        else
            warn "composer require failed - inspect the output above."
        fi
    else
        echo "Skipped."
    fi
fi

# Pinned to a specific commit (not `main`) of disrex-group/stylesmuggler-mitigation
# so this always fetches a reviewed, known-good revision instead of whatever
# happens to be on the branch tip when this script runs. Bump this if upstream
# publishes a newer/expanded guard.
PATCH_REPO_REF="994674fb2ce3abca54710f990332cb54f6ba8003"
PATCH_RAW_BASE="https://raw.githubusercontent.com/disrex-group/stylesmuggler-mitigation/${PATCH_REPO_REF}"

DI_SCANNER_PATCH_REL="patches/magento/magento2-base/stylesmuggler-di-scanner-guard.patch"
EMAIL_PREVIEW_PATCH_REL="patches/magento/module-email/stylesmuggler-preview-area-guard.patch"
DI_SCANNER_PATCH_FILE="$MAGENTO_ROOT/$DI_SCANNER_PATCH_REL"
EMAIL_PREVIEW_PATCH_FILE="$MAGENTO_ROOT/$EMAIL_PREVIEW_PATCH_REL"

# Downloads $1 to $2 using whichever of curl/wget is available.
fetch_url() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        warn "Neither curl nor wget is available - cannot download $url."
        return 1
    fi
}

# Prints the composer.json "extra" snippet the user needs, adjusted for
# whether the DI-scanner patch is being applied.
print_patches_json_snippet() {
    echo '  "extra": {'
    echo '      "composer-exit-on-patch-failure": true,'
    echo '      "patches": {'
    if [ -n "$APPLY_DI_SCANNER_PATCH" ]; then
        echo '          "magento/magento2-base": {'
        echo "              \"StyleSmuggler: DI code scanners are CLI-only (Sansec 2026-09-05, no CVE yet)\": \"$DI_SCANNER_PATCH_REL\""
        echo '          },'
    fi
    echo '          "magento/module-email": {'
    echo "              \"StyleSmuggler: email template preview is admin-area only (Sansec 2026-09-05)\": \"$EMAIL_PREVIEW_PATCH_REL\""
    echo '          }'
    echo '      }'
    echo '  }'
}

echo "Source (pinned commit, not 'main'): https://github.com/disrex-group/stylesmuggler-mitigation/tree/${PATCH_REPO_REF}"

if confirm "Download both patch files from disrex-group/stylesmuggler-mitigation @ ${PATCH_REPO_REF:0:7} for review?"; then
    mkdir -p "$(dirname "$DI_SCANNER_PATCH_FILE")" "$(dirname "$EMAIL_PREVIEW_PATCH_FILE")"

    FETCH_OK="1"
    if fetch_url "$PATCH_RAW_BASE/$DI_SCANNER_PATCH_REL" "$DI_SCANNER_PATCH_FILE"; then
        ok "Downloaded $DI_SCANNER_PATCH_REL"
    else
        warn "Failed to download $DI_SCANNER_PATCH_REL"
        FETCH_OK=""
    fi
    if fetch_url "$PATCH_RAW_BASE/$EMAIL_PREVIEW_PATCH_REL" "$EMAIL_PREVIEW_PATCH_FILE"; then
        ok "Downloaded $EMAIL_PREVIEW_PATCH_REL"
    else
        warn "Failed to download $EMAIL_PREVIEW_PATCH_REL"
        FETCH_OK=""
    fi

    if [ -n "$FETCH_OK" ]; then
        echo -e "\n${BOLD}--- $DI_SCANNER_PATCH_REL ---${NC}"
        cat "$DI_SCANNER_PATCH_FILE"
        echo -e "\n${BOLD}--- $EMAIL_PREVIEW_PATCH_REL ---${NC}"
        cat "$EMAIL_PREVIEW_PATCH_FILE"
        echo -e "\n${YELLOW}Review the diffs above before continuing.${NC}"

        # ---------------------------------------------------------------
        # Compatibility check (from the upstream patches/README.md):
        # guarding ClassesScanner::includeClass() is safe for stock
        # Magento, but mageplaza/module-admin-permissions calls it from an
        # HTTP-reachable admin controller (Controller/Adminhtml/Grid/Rescan.php).
        # ---------------------------------------------------------------
        COMPAT_HITS=$(grep -rl --include='*.php' \
            -e 'Di\\Code\\Reader\\ClassesScanner' \
            -e 'Di\\Code\\Scanner\\ArrayScanner' \
            -e 'Di\\Code\\Scanner\\XmlInterceptorScanner' \
            "$MAGENTO_ROOT/vendor" "$MAGENTO_ROOT/app/code" 2>/dev/null \
            | grep -v '/Test/' | grep -v '/magento2-base/setup/src/' | grep -v obsolete_ || true)

        APPLY_DI_SCANNER_PATCH="1"
        if [ -n "$COMPAT_HITS" ]; then
            warn "Found third-party code referencing the DI scanner classes outside tests:"
            echo "$COMPAT_HITS"
            warn "This looks like mageplaza/module-admin-permissions (or similar), which calls"
            warn "ClassesScanner from an HTTP-reachable admin controller (Grid/Rescan.php)."
            warn "Applying the DI-scanner CLI-only guard as-is may break that admin screen (500)."
            if ! confirm "Apply the magento/magento2-base DI-scanner patch anyway, understanding this risk?"; then
                echo "Skipped the magento/magento2-base patch. The magento/module-email front-door"
                echo "patch is the stronger of the two anyway (it makes the DI scanners unreachable"
                echo "in the first place) and has no such caveat."
                APPLY_DI_SCANNER_PATCH=""
            fi
        fi

        # ---------------------------------------------------------------
        # Wire composer.json extra.patches (merge, never overwrite)
        # ---------------------------------------------------------------
        JQ_APPLIED=""
        if command -v jq >/dev/null 2>&1; then
            if confirm "Automatically wire composer.json extra.patches via jq (backs up to composer.json.bak first)?"; then
                cp "$MAGENTO_ROOT/composer.json" "$MAGENTO_ROOT/composer.json.bak"

                # $emailPath/$diPath below are jq --arg names, not bash variables -
                # they must stay single-quoted so bash leaves them alone.
                JQ_FILTER='.extra //= {} | .extra["composer-exit-on-patch-failure"] = true | .extra.patches //= {}'
                # shellcheck disable=SC2016
                JQ_FILTER="$JQ_FILTER"' | .extra.patches["magento/module-email"] //= {} | .extra.patches["magento/module-email"]["StyleSmuggler: email template preview is admin-area only (Sansec 2026-09-05)"] = $emailPath'
                if [ -n "$APPLY_DI_SCANNER_PATCH" ]; then
                    # shellcheck disable=SC2016
                    JQ_FILTER="$JQ_FILTER"' | .extra.patches["magento/magento2-base"] //= {} | .extra.patches["magento/magento2-base"]["StyleSmuggler: DI code scanners are CLI-only (Sansec 2026-09-05, no CVE yet)"] = $diPath'
                fi

                if jq --arg emailPath "$EMAIL_PREVIEW_PATCH_REL" --arg diPath "$DI_SCANNER_PATCH_REL" \
                    "$JQ_FILTER" "$MAGENTO_ROOT/composer.json" > "$MAGENTO_ROOT/composer.json.tmp" \
                    && mv "$MAGENTO_ROOT/composer.json.tmp" "$MAGENTO_ROOT/composer.json"; then
                    ok "Wired extra.patches into composer.json (backup at composer.json.bak)."
                    JQ_APPLIED="1"
                else
                    warn "jq merge failed - composer.json was left untouched, see composer.json.bak."
                    rm -f "$MAGENTO_ROOT/composer.json.tmp"
                fi
            fi
        fi

        if [ -z "$JQ_APPLIED" ]; then
            echo "Add this to your composer.json 'extra' block by hand (merge with any existing entries):"
            print_patches_json_snippet
        fi

        # ---------------------------------------------------------------
        # Apply via composer install, then recompile DI
        # ---------------------------------------------------------------
        if [ -n "$JQ_APPLIED" ]; then
            if confirm "Run: ${COMPOSER_CMD[*]} install ?"; then
                if run_composer install; then
                    ok "composer install completed - patches should now be applied."

                    if confirm "Run: ${MAGENTO_CMD[*]} setup:di:compile ?"; then
                        if run_magento setup:di:compile; then
                            ok "setup:di:compile completed."
                        else
                            warn "setup:di:compile failed - inspect the output above."
                        fi
                    else
                        echo "Skipped setup:di:compile."
                    fi
                else
                    warn "composer install failed - inspect the output above."
                fi
            else
                echo "Skipped composer install - the patches are wired but not yet applied."
            fi
        else
            echo "Once you've added the extra.patches entry above, run:"
            echo "  ${COMPOSER_CMD[*]} install"
            echo "  ${MAGENTO_CMD[*]} setup:di:compile"
        fi

        echo -e "\nVerify the patch(es) took with:"
        echo "  grep -c 'StyleSmuggler mitigation' \\"
        [ -n "$APPLY_DI_SCANNER_PATCH" ] && echo "    $MAGENTO_ROOT/setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php \\"
        echo "    $MAGENTO_ROOT/vendor/magento/module-email/Block/Adminhtml/Template/Preview.php"
    else
        echo "One or more downloads failed - not touching composer.json. Retry, or get the"
        echo "patches manually from: https://github.com/disrex-group/stylesmuggler-mitigation/tree/${PATCH_REPO_REF}/patches"
    fi
else
    echo "Skipped. Full instructions (manual application, reverting, verification) are in"
    echo "https://github.com/disrex-group/stylesmuggler-mitigation/blob/${PATCH_REPO_REF}/patches/README.md"
fi

echo -e "${YELLOW}Neither patch removes any backdoor that may already be present on a${NC}"
echo -e "${YELLOW}compromised install (use stylesmuggler-helper.sh for that). Validate on${NC}"
echo -e "${YELLOW}staging first, and remove these once Adobe ships an official fix.${NC}"

# ----------------------------------------------------------------------
# Step 3: Webserver / WAF / PHP hardening snippets (file only, never applied)
# ----------------------------------------------------------------------
echo -e "\n${BLUE}${BOLD}[Step 3] Webserver / WAF / PHP hardening snippets${NC}"
echo "This only ever writes a local reference file for you to review and apply"
echo "yourself to your webserver/PHP config - it never edits live nginx/php.ini/"
echo "fstab config or restarts any service."

SNIPPET_FILE="./stylesmuggler-fix-snippets.txt"
if confirm "Write nginx/WAF/php.ini hardening snippets to $SNIPPET_FILE ?"; then
    cat > "$SNIPPET_FILE" <<'EOF'
StyleSmuggler - perimeter/OS hardening snippets (review before applying)
=========================================================================
These are perimeter/OS mitigations only. They do not patch the underlying
DI-compiler object-injection issue and are NOT applied by any script - copy
what applies to you into your own webserver/PHP config and reload the
relevant service yourself. Watch Adobe's security bulletins for the
official patch and retire these workarounds once it ships.

(The Graycore composer module and the DI-compiler hardening scaffold were
handled interactively by fix-magento-source.sh itself - see its Step 1/2 output.)

1) Cloudflare WAF rule:
(http.request.uri.path contains "/graphql" and (http.request.uri.query contains "styles%5B" or http.request.uri.query contains "styles[")) or (http.request.uri.query contains "generatorClass" or http.request.uri.query contains "with_resolved") or (http.request.uri.query contains "eval(base64_decode")

2) Nginx query-string filter (note: only inspects the query string, not
   POST body/JSON payloads - defense in depth only, not a complete block):
if ($query_string ~* "(styles(\[|%5B)|generatorClass|with_resolved|eval\(base64_decode)") {
    return 403;
}

3) If this shop uses a classic (Luma/Hyva) storefront with no headless/PWA
   frontend that needs GraphQL, consider disabling the endpoint entirely at
   the webserver level:
location /graphql {
    return 403;
}

4) php.ini - lock down process execution functions (watch out for
   proc_open specifically, observed droppers fall back to it when
   exec/system are blocked):
disable_functions = exec, passthru, shell_exec, system, proc_open, popen

5) Mount /tmp, /var/tmp, /dev/shm with the 'noexec' option to prevent
   downloaded ELF binaries from executing. This needs an /etc/fstab edit and
   a remount (or reboot) - not automated here since it can break other
   software on the same host that legitimately executes from a tmpdir;
   test on staging first.
EOF
    ok "Wrote $SNIPPET_FILE"
else
    echo "Skipped."
fi

echo -e "\n${GREEN}${BOLD}Done.${NC} This addresses proactive hardening only - it does not check for or"
echo -e "${GREEN}clean up an existing compromise. Run ./stylesmuggler-helper.sh for IoC"
echo -e "${GREEN}detection and incident-response cleanup. Keep watching Adobe's security${NC}"
echo -e "${GREEN}bulletins and replace these community workarounds with the official patch${NC}"
echo -e "${GREEN}once it ships.${NC}"
