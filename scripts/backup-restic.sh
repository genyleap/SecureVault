#!/usr/bin/env bash
# SecureVault v2 off-site snapshot coordinator.
# Intentionally NOT installed or enabled by cloning the repository.
set -Eeuo pipefail
umask 077

die() { printf 'SecureVault ERROR: %s\n' "$*" >&2; exit 1; }
on_error() { printf 'SecureVault FAILED at line %s (exit %s)\n' "$1" "$2" >&2; }
trap 'on_error "$LINENO" "$?"' ERR

[[ "${EUID}" == 0 ]] || die "Run as root via dedicated systemd service"
: "${RESTIC_REPOSITORY:?Set RESTIC_REPOSITORY to an independent off-site repository}"
: "${RESTIC_PASSWORD_FILE:?Set RESTIC_PASSWORD_FILE to a root-only key file}"
[[ -r "$RESTIC_PASSWORD_FILE" ]] || die "Repository password file is unreadable"

# Prevent accidentally counting backups to the VPS itself as off-site.
case "$RESTIC_REPOSITORY" in
  s3:*|sftp:*|rest:*|rclone:*|b2:*|gs:*|azure:*|swift:*) ;;
  *) die "Repository must be on independently operated off-site storage" ;;
esac

for cmd in restic runuser pg_dumpall mariadb-dump flock; do
  command -v "$cmd" >/dev/null 2>&1 || die "Required tool unavailable: $cmd"
done

for source in /var/www /opt /etc /boot; do
  [[ -d "$source" ]] || die "Required backup source missing: $source"
done

install -d -m 0700 /var/lib/securevault
install -d -m 0700 /run/securevault
exec 9>/run/securevault/backup.lock
flock -n 9 || die "Another SecureVault job is still active"

# "Snapshots" also checks that credentials, repository and transport work.
restic snapshots --latest 1 >/dev/null

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
echo "SecureVault: starting off-site backup generation $stamp"

# Restic encrypts bytes before they leave the source. Plaintext SQL never
# needs to be stored on the host. Pipefail propagates dump tool errors.
runuser -u postgres -- pg_dumpall \
  | restic backup --stdin --stdin-filename "postgresql-all.sql" \
      --tag securevault --tag postgresql --tag "$stamp"

mariadb-dump --all-databases --single-transaction --quick \
  --routines --events --triggers \
  | restic backup --stdin --stdin-filename "mariadb-all.sql" \
      --tag securevault --tag mariadb --tag "$stamp"

# Docker live volumes need application-consistent exports separately.
# Data under /opt and /var/www (including bind-mounted mail data) is
# captured as regular file snapshots; these are not DB PITR substitutes.
restic backup --one-file-system --exclude-caches \
  --tag securevault --tag files --tag "$stamp" \
  /var/www /opt /etc /boot

# Written only after *all three* remote backup stages succeeded.
printf '%s\n' "$stamp" > /var/lib/securevault/last_success
echo "SecureVault: COMPLETED all off-site stages for $stamp"
