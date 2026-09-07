#!/usr/bin/env bash
#
# StyleSmuggler (Sansec 0-Day RCE) - Remote GraphQL Exposure & Hardening Check
# Ref: https://sansec.io/research/stylesmuggler
#
# Sansec's writeup discloses IoCs (e.g. 'POST /graphql?styles[...]=...' as an
# access-log signature) but does NOT publish the full request/mutation needed
# to actually trigger the DI-compiler gadget chain, and no official Adobe
# patch/CVE existed at the time this script was written. That means there is
# NO reliable way to remotely confirm or rule out the underlying RCE from
# outside the server.
#
# What this script actually does instead: send a handful of harmless,
# read-only HTTP requests to a shop's public GraphQL endpoint to check
# EXPOSURE and MITIGATION-STATUS indicators - things the community
# mitigations in fix-magento-source.sh and stylesmuggler-hardening.txt
# either reduce or block:
#   1. Whether /graphql is reachable at all
#   2. Whether GraphQL introspection is enabled (larger attack surface)
#   3. Whether the published 'styles[...]' query-string attack signature is
#      filtered at the edge (WAF/nginx) or passes straight through
#   4. Whether /graphql has been disabled entirely at the webserver (the
#      strongest of the documented mitigations for headless-less storefronts)
#   5. Whether the /paypal/transparent/response/ endpoint used in the
#      second stage of the published attack chain is reachable (informational
#      only - it's normal Magento functionality, not itself a vulnerability)
#
# A "no risk indicators found" result is NOT proof the shop is unaffected -
# it only means the checks above found no exposure/missing-mitigation signal.
# It does not replace stylesmuggler-helper.sh (local IoC/compromise scan) or
# fix-magento-source.sh (source-level mitigation), and it never sends any
# payload capable of triggering code execution.
#
# Usage: ./stylesmuggler-remote-check.sh <SHOP_BASE_URL>
#
# Environment overrides:
#   STYLESMUGGLER_TIMEOUT=10   Per-request curl timeout in seconds
#   STYLESMUGGLER_INSECURE=1   Pass curl -k (skip TLS verification)

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

SHOP_BASE_URL="${1:-}"
if [ -z "$SHOP_BASE_URL" ]; then
    echo "Usage: $0 <SHOP_BASE_URL>" >&2
    echo "Example: $0 https://www.example.com" >&2
    exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required but was not found on PATH." >&2
    exit 3
fi

# Default to https:// if the caller passed a bare host/domain.
case "$SHOP_BASE_URL" in
    http://*|https://*) ;;
    *) SHOP_BASE_URL="https://$SHOP_BASE_URL" ;;
esac
SHOP_BASE_URL="${SHOP_BASE_URL%/}"
GRAPHQL_URL="$SHOP_BASE_URL/graphql"

CURL_OPTS=(-s -S -L --max-time "${STYLESMUGGLER_TIMEOUT:-10}")
if [ "${STYLESMUGGLER_INSECURE:-0}" = "1" ]; then
    CURL_OPTS+=(-k)
fi

RISK_ISSUES=0
HARDENING_FOUND=0

warn() {
    echo -e "${RED}[RISK] $1${NC}"
    RISK_ISSUES=$((RISK_ISSUES + 1))
}

ok() {
    echo -e "${GREEN}[OK] $1${NC}"
}

info() {
    echo -e "${BLUE}[*] $1${NC}"
}

harden() {
    echo -e "${GREEN}[HARDENED] $1${NC}"
    HARDENING_FOUND=$((HARDENING_FOUND + 1))
}

http_status() {
    curl "${CURL_OPTS[@]}" -o /dev/null -w '%{http_code}' "$@" 2>/dev/null
}

echo -e "${BLUE}=== StyleSmuggler remote GraphQL exposure check: $SHOP_BASE_URL ===${NC}\n"

# ----------------------------------------------------------------------
# 1. Base reachability
# ----------------------------------------------------------------------
info "1. Checking shop reachability..."
BASE_STATUS=$(http_status "$SHOP_BASE_URL/")
if [ -z "$BASE_STATUS" ] || [ "$BASE_STATUS" = "000" ]; then
    echo -e "${RED}Could not reach $SHOP_BASE_URL - check the URL, DNS, and network/proxy settings.${NC}" >&2
    exit 4
fi
ok "Shop responded with HTTP $BASE_STATUS."

# ----------------------------------------------------------------------
# 2. Is /graphql reachable, or blocked entirely at the edge?
# ----------------------------------------------------------------------
info "2. Checking /graphql endpoint..."
TYPENAME_QUERY='{"query":"{__typename}"}'
GQL_STATUS=$(http_status -X POST -H 'Content-Type: application/json' -d "$TYPENAME_QUERY" "$GRAPHQL_URL")

case "$GQL_STATUS" in
    403|404|410|451)
        harden "GraphQL endpoint returned HTTP $GQL_STATUS - appears blocked/disabled at the webserver level (matches the documented 'disable /graphql entirely' mitigation for non-headless storefronts)."
        echo ""
        echo -e "${BLUE}/graphql is not reachable, so the remaining GraphQL-specific checks are skipped.${NC}"
        GRAPHQL_REACHABLE=0
        ;;
    "")
        warn "No HTTP status received for /graphql (network error) - could not evaluate GraphQL exposure."
        GRAPHQL_REACHABLE=0
        ;;
    *)
        info "GraphQL endpoint is reachable (HTTP $GQL_STATUS)."
        GRAPHQL_REACHABLE=1
        ;;
esac

if [ "$GRAPHQL_REACHABLE" = "1" ]; then
    # --------------------------------------------------------------
    # 3. Introspection enabled?
    # --------------------------------------------------------------
    info "3. Checking whether GraphQL introspection is enabled..."
    INTROSPECTION_QUERY='{"query":"{__schema{queryType{name}}}"}'
    INTROSPECTION_RESPONSE=$(curl "${CURL_OPTS[@]}" -X POST -H 'Content-Type: application/json' \
        -d "$INTROSPECTION_QUERY" "$GRAPHQL_URL" 2>/dev/null || true)

    if echo "$INTROSPECTION_RESPONSE" | grep -q '"queryType"'; then
        warn "GraphQL introspection is enabled - the full schema can be enumerated by anyone, widening the attack surface for chaining GraphQL-based exploits. Consider disabling introspection in production."
    else
        ok "GraphQL introspection appears disabled or blocked."
    fi

    # --------------------------------------------------------------
    # 4. Is the published 'styles[...]' query-string signature filtered
    #    at the edge (WAF/nginx), or does it pass straight through?
    #    This sends only an inert marker value - no template/code payload -
    #    it never attempts to trigger execution.
    # --------------------------------------------------------------
    info "4. Probing whether the published 'styles[...]' attack signature is filtered at the edge..."
    PROBE_URL="${GRAPHQL_URL}?styles%5B0%5D=stylesmuggler-remote-check-probe"
    PROBE_STATUS=$(http_status -X POST -H 'Content-Type: application/json' -d "$TYPENAME_QUERY" "$PROBE_URL")

    case "$PROBE_STATUS" in
        403|406|444)
            harden "Request containing the 'styles[...]' query-string signature was blocked (HTTP $PROBE_STATUS) - a WAF/nginx filter matching the documented mitigation appears to be in place."
            ;;
        "")
            warn "No HTTP status received for the 'styles[...]' probe request (network error) - could not evaluate edge filtering."
            ;;
        *)
            warn "Request containing the 'styles[...]' query-string signature was NOT blocked (HTTP $PROBE_STATUS, same as an unfiltered GraphQL request) - no edge-level filter for this published attack signature was detected. See stylesmuggler-hardening.txt / fix-magento-source.sh for WAF/nginx rules to add."
            ;;
    esac
fi

# ----------------------------------------------------------------------
# 5. Second-stage endpoint reachability (informational only)
# ----------------------------------------------------------------------
info "5. Checking reachability of /paypal/transparent/response/ (used in the published attack chain's 2nd stage)..."
PP_STATUS=$(http_status "$SHOP_BASE_URL/paypal/transparent/response/")
if [ -n "$PP_STATUS" ] && [ "$PP_STATUS" != "000" ] && [ "$PP_STATUS" != "404" ]; then
    info "Endpoint responded with HTTP $PP_STATUS. This is normal, legitimate Magento functionality on stores with PayPal payment methods enabled - reachability alone is not a vulnerability. It's listed here only because Sansec's report shows it used in the published attack chain's execution stage."
else
    info "Endpoint not reachable/not found (HTTP ${PP_STATUS:-unknown}) - likely no PayPal payment method configured, or blocked."
fi

# ----------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------
echo ""
echo -e "${YELLOW}${BOLD}IMPORTANT:${NC}${YELLOW} this is an exposure/hardening-status check, not proof of${NC}"
echo -e "${YELLOW}vulnerability or safety. Sansec has not published the full exploit chain,${NC}"
echo -e "${YELLOW}so the underlying DI-compiler RCE cannot be confirmed or ruled out remotely.${NC}"
echo -e "${YELLOW}Run stylesmuggler-helper.sh on the server for local IoC/compromise checks,${NC}"
echo -e "${YELLOW}and fix-magento-source.sh on your dev environment to apply the documented${NC}"
echo -e "${YELLOW}source-level mitigations.${NC}"

echo ""
if [ "$RISK_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}=== RESULT: No exposure/missing-mitigation indicators found ($HARDENING_FOUND hardening signal(s) detected) ===${NC}"
    exit 0
fi

echo -e "${RED}=== RESULT: $RISK_ISSUES exposure/missing-mitigation indicator(s) found ($HARDENING_FOUND hardening signal(s) detected) ===${NC}"
exit 1
