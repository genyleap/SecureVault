# SecureVault disaster recovery runbook (C++23)

## System boundaries

The native C++23 `backup` executable handles full tar backups and safe
restoration. `securevault-ops` handles off-site encrypted Restic snapshots,
Restic inventory/integrity/isolated recovery, read-only database PITR auditing,
planning and MariaDB closed-binlog shipping. There are no Python sources or
Python test dependencies.

**Do not confuse availability of these commands with recoverability.**
The release is not production-certified until all off-site durability and
restore acceptance checks pass.

## Three independent backup layers

1. File/configuration snapshots: encrypt off-site with Restic. Include
   /var/www, /opt project data, /etc and /boot; separately audit all Docker
   bind mounts and volumes, encrypted secrets and external service data.
2. Physical database base backups: use compatible pgBackRest base backups
   for PostgreSQL and mariadb-backup for MariaDB, with successful isolated
   restoration. Logical SQL snapshots alone are insufficient for PITR.
3. Continuous transaction logs: ensure PostgreSQL WAL archival and MariaDB
   binlog continuity from the selected physical base backup to the target
   time, stored independently with retention and alerts.

Provider disk snapshots may accelerate boot recovery but cannot replace
encrypted independent data backups or PITR. Mirroring alone propagates
accidental deletion and corruption; protect retention independently.

## Encrypted Restic coordinator

```bash
securevault-ops restic list
securevault-ops restic generations
securevault-ops restic check
securevault-ops restic backup
```

The backup operation is explicit and Linux-only. A sample systemd service
and 15-minute timer are under `deploy/systemd/` but are not enabled by
building the project. Configure `RESTIC_REPOSITORY` and the root-only
`RESTIC_PASSWORD_FILE` on the operator-controlled backup host.
Create/initialize the independent repository before invoking the tool.
Test access, cost, capacity and restoration before scheduling anything.

The three logical/file Restic snapshots share a generation tag but are not
a transactionally atomic multi-database checkpoint. A fourth encrypted
`generation-committed` snapshot is written only after those three stages
succeed, containing a v2 JSON manifest with all three full snapshot IDs.
`securevault-ops restic generations` reads the encrypted manifest through
`restic dump` and checks that each listed ID matches exactly one component
snapshot in the repository. A missing or inaccessible manifest, duplicate
kind, or mismatch fails closed as `INCOMPLETE`. This verifies the identity
of the completed workflow, **not** a full cryptographic repository check
or a successful disaster-recovery drill. Older v1 or markerless generations
are conservatively shown as `INCOMPLETE` without deleting their data.

The log retention policy must be established separately; do not blindly
run `forget --prune` on object-locked buckets.

## Isolated restoration

```bash
securevault-ops restic restore --snapshot FULL_ID --kind files --target /new/directory
```

The destination must not exist. The command uses a private sibling staging
directory and no-overwrite atomic publication. It rejects restored symlinks
pointing outside the target. Exporting logical SQL requires the explicit
`--allow-plaintext-export` flag and does not restore a running database.

For database point-in-time recovery, run `securevault-ops pitr audit` on
an authorized host and generate review-only plans with
`securevault-ops pitr plan-postgresql` or `plan-mariadb`. The tool does not
automatically replay a binlog or change PostgreSQL configuration.

## Required production acceptance

- Verified independent, encrypted remote storage and off-host key custody
- Retention immutability and tested least-privilege credentials
- Verified PostgreSQL base backup plus continuous WAL archive with alerting
- Verified MariaDB physical base backup plus continuous binlog archive
- Detection of missing/stale backups and binlog gaps, with dedicated alerts
- Successful restore of both databases and files into a disposable recovery VM
- Measured recovery point/time objectives and documented failover procedure
- Backups validated against application state, permissions and restored content
- Cloud/provider failure drills without touching production data

**Zero loss cannot be guaranteed** by asynchronous backups; no local
configuration audit alone proves remote durability.
