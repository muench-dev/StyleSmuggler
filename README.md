# StyleSmuggler Helper

A bash script to detect and, optionally, help clean up **StyleSmuggler** — a
0-day RCE affecting Magento / Adobe Commerce.
Ref: https://sansec.io/research/stylesmuggler

## What it does

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

## Usage

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

## Disclaimer

This script is provided **as is, without warranty of any kind**. Any
cleanup/remediation you perform is entirely **at your own risk** — always
review the findings and each confirmation prompt carefully before proceeding.
