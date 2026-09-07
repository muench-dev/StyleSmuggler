#!/usr/bin/env bash
#
# StyleSmuggler (Sansec 0-Day RCE) Proactive Hardening / Fix Helper
# Ref: https://sansec.io/research/stylesmuggler
#
# Applies the community mitigations for the StyleSmuggler Magento/Adobe
# Commerce 0-day while no official Adobe patch exists yet:
#
#   1. Installs and enables the graycoreio/magento2-style-smuggler-patch
#      Composer module (executed against MAGENTO_ROOT, step by step).
#   2. Scaffolds (but does NOT auto-apply) a cweagans/composer-patches
#      setup for the "harden the DI-compiler scanners to CLI-only" approach
#      published by Disrex - the exact classes/methods aren't public in the
#      source advisory this script is based on, so a placeholder patch file
#      is written for you to fill in from the real writeup, never fabricated.
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
echo -e "\n${BLUE}${BOLD}[Step 2] DI-compiler CLI-only hardening (scaffold only)${NC}"
echo "The Disrex mitigation guards the 3 affected DI scanner classes in"
echo "magento/magento2-base so they abort with php_sapi_name() !== 'cli', closing"
echo "the include/require_once sink for HTTP requests while keeping"
echo "'bin/magento setup:di:compile' itself working."
echo -e "${YELLOW}The exact classes/methods to patch are not published in the advisory this${NC}"
echo -e "${YELLOW}script is based on, so this step only scaffolds the wiring - it will NOT${NC}"
echo -e "${YELLOW}fabricate or guess at a real code patch.${NC}"

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

PATCH_DIR="$MAGENTO_ROOT/patches"
PATCH_FILE="$PATCH_DIR/di-compiler-cli-only.patch.example"
if [ -f "$PATCH_FILE" ]; then
    ok "Placeholder patch file already exists at $PATCH_FILE."
else
    if confirm "Write a placeholder/instructions file to $PATCH_FILE ?"; then
        mkdir -p "$PATCH_DIR"
        cat > "$PATCH_FILE" <<'EOF'
StyleSmuggler - DI-compiler CLI-only hardening (Disrex approach)
==================================================================
This is NOT a real patch. It is a placeholder that tells you what to do,
because the exact classes/methods to patch are not published in the source
advisory this repo's scripts are based on and must not be guessed at.

What the real patch needs to do (per the advisory):
  In the 3 affected DI-scanner classes under magento/magento2-base that
  accept an external file path and hand it directly to include/require_once
  (intended only for `bin/magento setup:di:compile` on the CLI, but
  historically also reachable over HTTP), add a hard guard at the top of the
  relevant method(s):

      if (PHP_SAPI !== 'cli') {
          throw new \RuntimeException('This DI scanner is CLI-only.');
      }

  (or equivalent: `php_sapi_name() !== 'cli'`)

How to get the real patch:
  1. Read the Disrex writeup for the exact class names/line numbers for your
     installed magento/magento2-base version:
     https://www.disrex.nl/blogs/stylesmuggler-magento-zero-day
  2. Generate/obtain a real unified diff against YOUR vendor/magento/... tree
     (versions differ - a patch for 2.4.7 will not cleanly apply to 2.4.9).
  3. Verify the diff by hand against your own vendor source before use.
  4. Save it as e.g. patches/di-compiler-cli-only.patch (drop the .example
     suffix) and wire it into composer.json, e.g.:

       "extra": {
           "patches": {
               "magento/magento2-base": {
                   "StyleSmuggler: CLI-only guard on DI scanners": "patches/di-compiler-cli-only.patch"
               }
           }
       }

  5. Run `composer install` (or `composer update magento/magento2-base`) to
     apply it, then `bin/magento setup:di:compile` to confirm the CLI path
     still works.

This script does NOT add the "extra.patches" entry above to your
composer.json automatically, since there is no real patch file to point it
at yet.
EOF
        ok "Wrote $PATCH_FILE"
    else
        echo "Skipped."
    fi
fi

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
