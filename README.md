# StyleSmuggler Helper Scripts

Two bash scripts to deal with **StyleSmuggler** — a 0-day RCE affecting
Magento / Adobe Commerce.
Ref: https://sansec.io/research/stylesmuggler

- `stylesmuggler-helper.sh` — **detect** an existing compromise and, if
  found, walk through **incident-response cleanup**. Run this directly on
  the **server/hosting environment** (production, staging, or Cloud node)
  you want to check — not on your local machine.
- `fix-magento-source.sh` — **proactively harden** a Magento/Adobe Commerce
  install against the vulnerability while no official Adobe patch exists.
  Run this on your **local development environment** (or wherever you edit
  and commit the Magento source/Composer dependencies) — it patches the
  source code, which you then deploy through your normal release process.

Use both: run `fix-magento-source.sh` to apply mitigations, and run
`stylesmuggler-helper.sh` periodically (and immediately if you suspect an
incident) to check for IoCs.

Both scripts run on Linux and macOS (e.g. a developer's Mac driving a local
ddev/Warden Magento environment) — CI runs ShellCheck and a functional smoke
test on `ubuntu-latest` and `macos-latest` on every push. `ps`/`sed`/`netstat`
usage is written to work with both GNU (Linux) and BSD (macOS) userlands.

## `stylesmuggler-helper.sh` — detection & incident-response cleanup

> **Run this on the server environment**, not your local machine — it scans
> the live filesystem, running processes, crontabs, and logs of the host
> it's executed on, so it must run where the (possibly compromised)
> Magento/Adobe Commerce install actually serves traffic.

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
- `LOG_DIR` — path to webserver access logs, file or directory. If omitted,
  it's auto-detected using the `MAGENTO_CLOUD_PROJECT` environment variable
  that Adobe Commerce Cloud sets automatically (it holds the project ID):
  if `/var/log/platform/<project-id>` exists (Pro Staging/Production), that
  path is used; otherwise it falls back to `/var/log` (Dev environments,
  on-prem, local).

Example:

```bash
./stylesmuggler-helper.sh /var/www/magento /var/log/nginx
```

Re-run some checks (cron spool, non-root process scan) as root/sudo to
cover other system users, e.g. the webserver account.

### Checking an Adobe Commerce Cloud (ACCS/Pro) system

On Adobe Commerce Cloud, the writable filesystem lives under `/mnt/var`
(mounted from `/app/var` inside the container) and the application code is
deployed read-only under `/app`. SSH into the environment you want to check
(e.g. `magento-cloud ssh -e <environment>`), then clone and run the helper
directly from there:

```bash
cd /mnt/var
git clone https://github.com/muench-dev/StyleSmuggler.git
cd ./StyleSmuggler
./stylesmuggler-helper.sh /app
```

- `/mnt/var` is writable on Cloud containers, so it's a safe place to clone
  the repo without touching the deployed `/app` code.
- `/app` is passed as `SHOP_DIR` so the script scans the actual deployed
  Magento root.
- `LOG_DIR` (2nd argument) is left out on purpose: the script auto-detects
  it using the `MAGENTO_CLOUD_PROJECT` environment variable that Adobe
  Commerce Cloud sets automatically on every node (it holds the project
  ID) — using `/var/log/platform/<project-id>` on Pro Staging/Production
  when that path exists, and falling back to `/var/log` on Dev
  environments. The script prints which `LOG_DIR` it auto-detected. Pass
  an explicit second argument any time to override this, e.g.
  `./stylesmuggler-helper.sh /app /var/log/platform/<project-id>`.

Repeat this on each environment/node you want to check (and on each web
node if your plan runs more than one), since the scan only covers the
local filesystem, processes, and logs of the container it runs on.

## `fix-magento-source.sh` — proactive hardening / mitigation

> **Run this on your local development environment**, not on a live server
> — it patches the Magento source code and Composer dependencies (via
> `composer require`, `setup:upgrade`, `setup:di:compile`), so it belongs in
> your normal dev workflow, to be committed and deployed like any other
> code change rather than applied directly in production.

Applies the community mitigations for StyleSmuggler documented while no
official Adobe patch exists yet:

1. Installs and enables the `graycoreio/magento2-style-smuggler-patch`
   Composer module against the Magento install (`composer require`,
   `module:enable`, `setup:upgrade`, `setup:di:compile`) — this hardening
   module blocks the `{{block}}` directive in email templates, adds strict
   class validation before instantiation in the grid-row URL generator
   factory, and breaks open PHP tags inside fatal Web API error reports to
   prevent log/report poisoning.
2. Downloads and applies, via `cweagans/composer-patches`, the two real
   source patches Disrex has published for the root cause:
   - `magento/module-email` — the **front door**: the email template preview
     block renders `{{block}}` template directives from an unauthenticated
     request; guarded to admin-area-only, which makes the whole gadget chain
     unreachable. Disrex calls this the stronger of the two.
   - `magento/magento2-base` — the **sink**: the 3 DI-compiler scanner
     classes that `include`/`require_once` a caller-supplied path, guarded
     to CLI-only so `bin/magento setup:di:compile` keeps working.

   Both are fetched from a **pinned commit** of
   `disrex-group/stylesmuggler-mitigation` (not the `main` branch, to avoid
   a moving-target supply-chain risk) and printed in full for you to review
   before anything is wired into `composer.json`. Before applying the
   DI-scanner patch, it also runs the compatibility check from the upstream
   README: some third-party modules (e.g.
   `mageplaza/module-admin-permissions`) call `ClassesScanner` from an
   HTTP-reachable admin controller, and guarding it there would break that
   admin screen — if such a reference is found, the script warns and asks a
   separate, explicit confirmation before applying that part of the patch,
   or lets you skip it and keep only the front-door patch. `composer.json`
   wiring is done via `jq` when available (with a `composer.json.bak`
   backup first); otherwise the exact JSON to add by hand is printed.
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

### ddev / Warden support

The script auto-detects local dev environments and runs Composer/`bin/magento`
through them instead of directly on the host:

- **ddev** — detected via a `.ddev` directory in `MAGENTO_ROOT`; runs
  `ddev composer ...` and `ddev exec bin/magento ...`.
- **Warden** — detected via `WARDEN_ENV_NAME=` in `MAGENTO_ROOT/.env`; runs
  `warden env exec -T php-fpm composer ...` and
  `warden env exec -T php-fpm bin/magento ...`. Override the service name
  with `WARDEN_PHP_SERVICE` if your project doesn't use `php-fpm`.
- Otherwise falls back to plain **native** `composer`/`bin/magento` on the
  host.

If a project marker is found but the matching CLI (`ddev`/`warden`) isn't on
`PATH`, the script warns and falls back to native. Force a specific mode
with `FIX_MAGENTO_ENV=ddev|warden|native` if detection picks the wrong one.
Every confirmation prompt shows the exact resolved command (e.g.
`Run: ddev composer require ... ?`) before it runs.

### Usage

```bash
./fix-magento-source.sh [MAGENTO_ROOT]
```

- `MAGENTO_ROOT` — path to the Magento/Adobe Commerce root (default: `.`)

Example:

```bash
./fix-magento-source.sh /var/www/magento

# Force a mode instead of auto-detecting:
FIX_MAGENTO_ENV=warden WARDEN_PHP_SERVICE=php ./fix-magento-source.sh /var/www/magento
```

## Disclaimer

Both scripts are provided **as is, without warranty of any kind**. Any
cleanup, remediation, or hardening action you perform is entirely **at
your own risk** — always review the findings and each confirmation
prompt carefully before proceeding.
