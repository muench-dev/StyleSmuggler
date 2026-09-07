# AGENTS.md

StyleSmuggler is a set of incident-response and hardening shell scripts for the
Sansec-disclosed StyleSmuggler 0-day RCE affecting Magento/Adobe Commerce
(https://sansec.io/research/stylesmuggler). None of the scripts patch Magento
core themselves without confirmation, and none apply live webserver/OS config
changes automatically - every state-changing action prompts for explicit y/N
confirmation first.

## Shell scripts

Every change to a `.sh` file must be verified with `shellcheck` before being considered done.

```bash
shellcheck path/to/script.sh
```

### stylesmuggler-helper.sh

`./stylesmuggler-helper.sh [SHOP_DIR] [LOG_DIR]`

Detects Indicators of Compromise (IoCs) for an *already exploited* host:
rogue kworker/fc-cache/gvfsd-user/chronyd implant processes, cron
persistence (crontab, cron.d, and root-only cron spool files), dropper
files under `/tmp`/home dirs, poisoned `var/report`/`var/log` payloads, a
web-shell pattern in the product-image cache, known malware sample hashes,
active sockets to published C2 IPs, and attack signatures in webserver
access logs. It also reports whether the DI-compiler scanner CLI-only
guard (the root-cause fix) is already present in the codebase.

If run interactively and issues are found, it offers a guided 6-step
remediation wizard (evidence preservation reminder, cron cleanup, kill
malicious processes, quarantine implant files, Redis session flush,
credential-rotation checklist) plus an optional file-only nginx/WAF/php.ini
hardening writeup - it never edits live server config itself.

### fix-magento-source.sh

`./fix-magento-source.sh [MAGENTO_ROOT]`

Proactively applies the community source-level mitigations while no
official Adobe patch exists: installs the
`graycore/magento2-style-smuggler-patch` Composer module, and downloads +
(with confirmation) wires in the two Disrex patches for the actual root
cause - the `magento/module-email` template-preview "front door" and the
`magento/magento2-base` DI-compiler scanner "sink" - via
`cweagans/composer-patches`, pinned to a fixed upstream commit. Detects
ddev/Warden/native environments automatically. Does not detect or clean up
an existing compromise - use `stylesmuggler-helper.sh` for that.

### stylesmuggler-remote-check.sh

`./stylesmuggler-remote-check.sh <SHOP_BASE_URL>`

Read-only, unauthenticated remote check against a shop's public `/graphql`
endpoint: reachability, whether introspection is enabled, whether the
published `styles[...]` query-string attack signature is filtered at the
edge (WAF/nginx), whether `/graphql` is disabled entirely, and whether the
`/paypal/transparent/response/` second-stage endpoint is reachable. It
never sends a payload capable of triggering code execution and cannot
confirm or rule out the underlying RCE - it only reports exposure and
mitigation-status signals.
