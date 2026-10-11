# PostgreSQL and MariaDB PITR readiness (native C++23)

The `securevault-ops` C++23 binary inspects local database prerequisites
with read-only SQL and generates review-only recovery plans. It never runs
database Restore, changes server configuration, rotates binary logs, or
installs dependencies.

## Read-only audit

```bash
securevault-ops pitr audit
```

The PostgreSQL audit queries `current_setting` and `pg_stat_archiver`
for `wal_level`, `archive_mode`, `archive_command/archive_library`
presence (without revealing secret-bearing command text), `full_page_writes`,
and archiver success/failure counters. It checks for `pgbackrest` in PATH.

The MariaDB audit uses `SHOW GLOBAL VARIABLES` to inspect `log_bin`,
`binlog_format` and `server_id`, plus local availability of
`mariadb-backup` and a binlog replay tool. Results are JSON.
Even all-local-pass does **not** establish that WAL/binlogs exist remotely
or that a restore to a given timestamp is possible.

## Isolated, review-only recovery plans

```bash
securevault-ops pitr plan-postgresql --stanza genyleap \
  --target-time '2026-10-10T02:00:00Z' \
  --dest /srv/securevault-recovery/new-postgresql

securevault-ops pitr plan-mariadb \
  --target-time '2026-10-10T02:00:00Z' \
  --dest /srv/securevault-recovery/new-mariadb
```

The target time must be ISO 8601 with an explicit timezone, must be in
the past, and the destination must be a previously nonexistent subdirectory
under an existing `/srv/securevault-recovery` root. The program prints a
plan and **does not execute it**. Real recovery needs matching database
versions, verified base backups, an uninterrupted log chain, and a dedicated
stopped recovery instance. MariaDB requires confirmation of binlog offsets,
GTIDs and transaction boundaries before any manual replay.

## MariaDB closed-binlog shipping

Create a 0600 JSON configuration stored outside version control, e.g.:

```json
{
  "instance_id": "genyleap-main",
  "binlog_prefix": "mysql-bin",
  "binlog_dir": "/var/lib/mysql",
  "state_file": "/var/lib/securevault/binlog-state.json",
  "db_defaults_file": "/etc/securevault/mariadb-client.cnf"
}
```

The `db_defaults_file` must be root-only 0600. Set
`RESTIC_REPOSITORY` to an independently hosted encrypted Restic repository
and `RESTIC_PASSWORD_FILE` to a private 0600 key file. No credentials
are read from command-line arguments or committed to Git.

```bash
securevault-ops binlog ship --config /etc/securevault/binlog.json
# Explicitly allow writes only after a verified dry run and base backup:
securevault-ops binlog ship --config /etc/securevault/binlog.json --execute
```

Dry-run queries `SHOW BINARY LOGS` and `SHOW MASTER STATUS` and checks
local closed log availability and continuity. Execute uploads each closed
binlog as an authenticated encrypted Restic snapshot, compares local
content-change fingerprints before/after and advances a private state
checkpoint only after Restic acknowledges the upload.

The **active** MariaDB binlog is not uploaded. Rotating/purging logs is
not automated. An existing checkpoint cannot be a symlink, including a
dangling symlink. The checkpoint file and its parent directory are synchronized
before shipping success is reported; sync failures cause a nonzero result.
If a closed log changes during upload or a sequence gap appears, the
checkpoint will not advance for that segment.

For complete PITR, a separate physical base backup and continuous non-gapped
shipping must be operational and independently tested; the presence of logs
or a successful local audit is not enough.
