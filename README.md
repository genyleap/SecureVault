# SecureVault

SecureVault is a native **C++23** disaster-recovery toolkit for Linux and macOS.
There is **no Python runtime, no Python test suite, and no scripting-language
implementation of backup or recovery logic**. All operational commands and
regression tests are written in C++23.

## Architecture

- `backup`: original C++23 full tar.gz backup / verify / safe staged restore,
  MariaDB/PostgreSQL logical exports and optional SFTP.
- `securevault-ops`: C++23 orchestration for encrypted Restic backup and
  recovery, PostgreSQL/MariaDB PITR prerequisite inspection and plans,
  and safe shipping of **closed** MariaDB binary-log segments.
- `tests/native_tests.cpp`: C++23 mock-backed system, security and continuity tests.
- `tests/backup_tests.cpp`: C++23 integration tests of the original archive engine.
- `deploy/systemd/`: optional Linux service and 15-minute timer templates;
  no service is installed or activated automatically.

**Not production-certified:** Continuous PostgreSQL WAL archive, independent
storage retention and immutability, durable physical database base backups,
end-to-end disaster recovery and RPO/RTO measurements still require
configuration and real restoration drills.

## Build

Linux prerequisites: CMake, a C++23-capable compiler, libarchive, libssh,
libcurl, zlib and JsonCpp development headers. On macOS use Homebrew LLVM
and `brew install cmake ninja llvm libarchive libssh curl jsoncpp zlib`.

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

On macOS you can explicitly select
`-DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++`.
Use a fresh build directory after changing compilers. CMake never installs
Homebrew packages automatically.

For testing the new native operations without the older archive engine:

```bash
cmake -S . -B build-ops -G Ninja -DSECUREVAULT_BUILD_CORE=OFF
cmake --build build-ops --parallel
ctest --test-dir build-ops --output-on-failure
```

## Legacy archive engine

```bash
./build/backup --config backup_config.json daily
./build/backup verify /path/to/system-backup.tar.gz
./build/backup restore /path/to/system-backup.tar.gz /new/nonexistent/destination
```

The unsafe timestamp-only incremental implementation remains disabled.
Restoration rejects traversal, special files and unsafe links and never
deliberately overwrites an existing destination. Tar/SQL exports from the
legacy engine are **not encrypted at rest**.

## Native encrypted Restic operations

Set `RESTIC_REPOSITORY` to an **independent off-host** Restic repository
and `RESTIC_PASSWORD_FILE` to a private 0600 password file. Configure
storage access separately using least-privilege credentials. No secrets
should be committed or supplied directly on the command line.

```bash
securevault-ops restic list
securevault-ops restic generations
securevault-ops restic check
securevault-ops restic restore --snapshot FULL_64_HEX_ID --kind files --target /new/restore
```

The `generations` command checks the presence of all three tagged snapshots
(files, PostgreSQL, MariaDB), not cross-service transactional consistency.
`check` reads repository data and may incur network/storage charges.

Recovery is fail-closed: before a restored directory becomes visible at its
destination, SecureVault rejects files with multiple hard links, FIFO/socket
or device entries, absolute/escaping symlinks, and incomplete extractions.
Safe relative symlinks remain supported. **Hardlinked regular files are
deliberately not yet supported**, even if they originated from valid snapshots.
The target directory must not already exist, including in a concurrent race.

For a database SQL export use `--kind postgresql` or
`--kind mariadb` and **explicitly** add `--allow-plaintext-export`.
The command restores only into a new directory; it never imports SQL into
a running database. Plaintext SQL must be protected and disposed of safely.

The manual Linux-only encrypted off-site coordinator is:

```bash
securevault-ops restic backup
```

It requires suitable privileges and independently initialized Restic storage.
It streams logical database dumps into encrypted Restic snapshots and then
takes a file snapshot. It is **not PITR** and does not include all live Docker
volume consistency guarantees. A tagged generation can be incomplete if a
step fails; the success marker is written only after all steps succeed.

## Database PITR readiness and closed-binlog shipping

```bash
securevault-ops pitr audit
securevault-ops pitr plan-postgresql --stanza genyleap \
  --target-time '2026-10-10T02:00:00+00:00' \
  --dest /srv/securevault-recovery/postgresql-new
securevault-ops pitr plan-mariadb \
  --target-time '2026-10-10T02:00:00+00:00' \
  --dest /srv/securevault-recovery/mariadb-new
securevault-ops binlog ship --config /etc/securevault/binlog.json
```

The binlog command defaults to a non-mutating **dry run**. Add `--execute`
only after checking the configuration, base backup and remote storage.
The active log is never shipped; only closed logs are eligible, with
continuity checks and a checkpoint written after acknowledged upload.
See [PITR-READINESS.md](PITR-READINESS.md) and
[DISASTER-RECOVERY.md](DISASTER-RECOVERY.md).

## Safety

No code checkout, CMake build or `ctest` run enables production backup,
rotates logs, modifies database configuration, or starts an automatic restore.
A real disaster recovery test on a disposable host is mandatory before
production use. Keep a separate independently encrypted backup **now**;
do not depend on unfinished SecureVault development as your sole backup.
