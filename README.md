# StyleSmuggler Helper Scripts

Two bash scripts to deal with **StyleSmuggler** — a 0-day RCE affecting
Magento / Adobe Commerce.
Ref: https://sansec.io/research/stylesmuggler

- `stylesmuggler-helper.sh` — **detect** an existing compromise and, if
  found, walk through **incident-response cleanup**.
- `fix-magento-source.sh` — **proactively harden** a Magento/Adobe Commerce
  install against the vulnerability while no official Adobe patch exists.

Use both: run `fix-magento-source.sh` to apply mitigations, and run
`stylesmuggler-helper.sh` periodically (and immediately if you suspect an
incident) to check for IoCs.

## `stylesmuggler-helper.sh` — detection & incident-response cleanup

Scans the local system for known Indicators of Compromise (IoCs):

1. Running processes (kworker/fc-cache/gvfsd-user masquerading implants)
2. Crontabs (current user, `/etc/cron.d`, and — with root/sudo — other users' cron spool files)
3. Filesystem dropper/implant paths in `/tmp` and the user's home directory
4. Magento `var/report` / `var/log` for injected payload traces and related PHP errors
5. Active network sockets connecting to known C2 IPs
6. Web access logs for exploitation request patterns

If run in an interactive terminal and issues are found, it offers a guided,
step-by-step remediation wizard (forensic preservation reminder, cron
cleanup, process termination, file quarantine, Redis session invalidation,
a credential-rotation checklist, and optional nginx/WAF/php.ini hardening
suggestions written to a local file). **Every remediation action asks for
explicit confirmation before it runs**, and nothing is ever applied to
live Magento or webserver configuration automatically.

The script never installs, upgrades, or modifies the Magento application
itself — it only inspects the OS/filesystem/logs and cleans up OS-level
implant artifacts if you confirm each step.

### Usage

```bash
./stylesmuggler-helper.sh [SHOP_DIR] [LOG_DIR]
```

- `SHOP_DIR` — path to the Magento/Adobe Commerce root (default: `.`)
- `LOG_DIR` — path to webserver access logs, file or directory (default: `/var/log`)

Example:

```bash
./stylesmuggler-helper.sh /var/www/magento /var/log/nginx
```

Re-run some checks (cron spool, non-root process scan) as root/sudo to
cover other system users, e.g. the webserver account.

## `fix-magento-source.sh` — proactive hardening / mitigation

Applies the community mitigations for StyleSmuggler documented while no
official Adobe patch exists yet:

1. Installs and enables the `graycoreio/magento2-style-smuggler-patch`
   Composer module against the Magento install (`composer require`,
   `module:enable`, `setup:upgrade`, `setup:di:compile`) — this hardening
   module blocks the `{{block}}` directive in email templates, adds strict
   class validation before instantiation in the grid-row URL generator
   factory, and breaks open PHP tags inside fatal Web API error reports to
   prevent log/report poisoning.
2. Scaffolds (but does **not** auto-apply) a `cweagans/composer-patches`
   setup for the DI-compiler "CLI-only" hardening approach published by
   Disrex. The exact classes/methods to patch aren't published in the
   source advisory this script is based on, so it writes a placeholder
   `patches/di-compiler-cli-only.patch.example` file with instructions to
   obtain and verify the real patch yourself — it never fabricates a code
   patch or guesses at class names.
3. Writes webserver/WAF/php.ini/OS hardening suggestions (Cloudflare WAF
   rule, nginx query-string filter, optional `/graphql` endpoint block,
   `disable_functions` for PHP, `noexec` mount advice for `/tmp`,
   `/var/tmp`, `/dev/shm`) to a local `stylesmuggler-fix-snippets.txt` file
   for manual review.

**Every state-changing step asks for explicit y/N confirmation first.**
Steps 1–2 actually execute Composer/`bin/magento` commands against the
Magento root once confirmed. Step 3 **never** edits live nginx/php.ini/
fstab configuration or restarts any service — it only ever writes a local
snippet file for you to apply yourself.

This script does not detect or clean up an existing compromise — use
`stylesmuggler-helper.sh` for that. Administrators must also note the
Graycore module is a hardening measure, not a fix for the structural root
cause in the DI compiler, and does not remove any backdoor that may
already be present. Validate on a staging system before production.

### Usage

```bash
./fix-magento-source.sh [MAGENTO_ROOT]
```

- `MAGENTO_ROOT` — path to the Magento/Adobe Commerce root (default: `.`)

Example:

```bash
./fix-magento-source.sh /var/www/magento
```

## Disclaimer

Both scripts are provided **as is, without warranty of any kind**. Any
cleanup, remediation, or hardening action you perform is entirely **at
your own risk** — always review the findings and each confirmation
prompt carefully before proceeding.
