# SecureVault

A **native C++23 encrypted snapshot and recovery engine**, without the
Restic executable, a Python runtime or shell scripts. The new primary
program is `securevault-vault`. The deprecated unencrypted tar/database
core and Restic compatibility tooling are disabled by default.

**Release status:** development candidate, not certified disaster recovery.
See [RELEASE-READINESS.md](RELEASE-READINESS.md) for the remaining external
acceptance requirements.

## Design

- **SVLT v2** encrypted container with AES-256-GCM authenticated encryption
  provided by OpenSSL 3; an independent fresh 128-bit salt and 96-bit nonce
  for each snapshot, with `scrypt` (N=32768, r=8, p=1) key derivation.
  The v2 reader also accepts legacy SVLT v1 files.
- Snapshot paths are **SHA-256 fingerprints of the encrypted file bytes**
  (`<64 lowercase hex>.svlt`). Download checks both this identity and the
  authenticated encryption tag. Older, randomly named SVLT snapshots may
  still be opened and restored locally.
- Streaming backup and restore of regular files, empty directories and safe
  relative symlinks, with no overwrite of an existing target.
- Native **encrypted logical database exports** from `pg_dumpall` and
  `mariadb-dump` process stdout directly through C++ pipes into SVLT.
  **No plaintext SQL staging files.** A failing or stalled dump cannot
  publish a successful snapshot. Even after stdout reaches EOF, the
  producer must exit before its deadline; otherwise SecureVault kills it
  and refuses publication. An isolated restore produces an SQL file,
  never imports it automatically into a running database.
- Optional independent **HTTPS transport using libcurl**, supporting
  conditional PUT with `If-None-Match: *`, TLS verification, no redirects,
  downloaded-ciphertext fingerprint verification, full GCM authentication,
  and atomic publication into a private repository. No Restic calls.

The cipher and TLS implementation use maintained libraries, not homemade
cryptographic primitives. The encrypted file layout and filesystem
safety checks are implemented in C++23.

## Dependencies and building

A C++23 compiler, CMake 3.26+, **OpenSSL 3** development files, and
**libcurl** development files. No JSONCPP, libarchive, libssh or Restic
is required for the default native build. Those other dependencies are
only used by deliberately enabled legacy compatibility targets.

On macOS (Homebrew dependencies `llvm`, `openssl@3`, `curl`,
`cmake` and `ninja` if needed):

```bash
cmake -S . -B build-macos-native -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
  -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 \
  -DSECUREVAULT_BUILD_CORE=OFF \
  -DSECUREVAULT_LEGACY_RESTIC=OFF
cmake --build build-macos-native --parallel
ctest --test-dir build-macos-native --output-on-failure -V
```

On Linux, the same CMake/CTest sequence works without the macOS compiler
and OpenSSL paths. No CMake or CTest action installs or starts a scheduler,
modifies a database, or deploys services.

## Local encrypted snapshots

Create a dedicated private repository and keep a strong password file in
a separate protected location (mode `0600`). **Never put the password
file inside the source tree or repository**; SecureVault rejects this
mistake. Paths below are examples, not commands to run against live data.

```bash
securevault-vault init --repo /absolute/private/vault
securevault-vault create \
  --repo /absolute/private/vault \
  --source /absolute/test-data \
  --password-file /absolute/secret/keyfile
securevault-vault list --repo /absolute/private/vault
securevault-vault verify \
  --snapshot /absolute/private/vault/SHA256_HEX.svlt \
  --password-file /absolute/secret/keyfile
securevault-vault restore \
  --snapshot /absolute/private/vault/SHA256_HEX.svlt \
  --target /absolute/new-recovery \
  --password-file /absolute/secret/keyfile
```

The restore target must not exist. Decryption is fully authenticated
before extraction; files are published only after a second successful
authentication during extraction. Files are created mode `0600` and
directories mode `0700`. Traversal, unsafe or absolute symlinks, hardlinks,
special file types and duplicate archive entries are rejected.

## Logical database backups (experimental)

Requires `pg_dumpall` or `mariadb-dump` to be installed and have
database access. Configure secure authentication using the database
client's protected environment or password-file configuration,
**not credentials on the command line**.

```bash
securevault-vault database-backup --database postgresql \
  --repo /absolute/private/vault \
  --password-file /absolute/secret/keyfile

securevault-vault database-backup --database mariadb \
  --repo /absolute/private/vault \
  --password-file /absolute/secret/keyfile
```

These snapshots restore to `postgresql-all.sql` or `mariadb-all.sql`
inside a newly created restore directory. They do not directly restore a
database, capture a transactionally consistent checkpoint across engines,
or provide physical PostgreSQL WAL/MariaDB binlog PITR.

## Native encrypted backup generations (experimental)

Create one logical generation consisting of an encrypted file snapshot,
PostgreSQL dump and MariaDB dump. A **fourth, encrypted commit snapshot**
(`manifest.svgen`) is written only when all three components succeed.
Its content identifies each component's 64-character SHA-256 snapshot ID.
The verifier authenticates the marker, checks the referenced ciphertext
fingerprints and individually verifies all three GCM tags.

```bash
securevault-vault generation-create \
  --repo /absolute/private/vault \
  --source /absolute/test-data \
  --password-file /absolute/secret/keyfile

securevault-vault generation-verify \
  --repo /absolute/private/vault \
  --snapshot /absolute/private/vault/MANIFEST_SHA256.svlt \
  --password-file /absolute/secret/keyfile
```

If a stage fails, the commit marker is **not written**. Earlier component
snapshots may remain as *uncommitted encrypted snapshots* and are never
silently treated as a successful generation. There is no automatic deletion
of these or other backups. This is a **local** multi-component commit marker,
not an atomic cross-database transaction or an off-site completion receipt.
The operator must independently replicate and test-recover the four encrypted
objects. Physical base backups, WAL/binlog PITR and cross-database consistency
remain out of scope for this implementation.

## HTTPS off-site transport (experimental)

Provision a service that accepts **single-object HTTPS PUT with the
conditional header `If-None-Match: *`**, returning HTTP 412 if the object
already exists. For S3-compatible storage, use a short-lived pre-signed
PUT URL for the exact object path and sign its required headers. A
**different** pre-signed GET URL retrieves that object. Keep each URL in
a private `0600` file; do not paste signed URLs into shell arguments,
Git commits or logs.

```bash
securevault-vault upload \
  --snapshot /absolute/private/vault/SHA256_HEX.svlt \
  --password-file /absolute/secret/keyfile \
  --url-file /absolute/secret/presigned-put-url

securevault-vault download \
  --repo /absolute/private/second-vault \
  --snapshot-id SHA256_HEX \
  --password-file /absolute/secret/keyfile \
  --url-file /absolute/secret/presigned-get-url
```

TLS trust comes from the system CA store. `--ca-file /absolute/ca.pem`
may be supplied for a separately trusted private CA. HTTPS transfers
reject HTTP, redirects, URL files with insecure permissions, and URL files
that are symlinks. Download requires an empty destination name and refuses
to publish a changed ciphertext or an incorrectly authenticated archive.
The remote endpoint **must honor create-only semantics**; SecureVault
cannot guarantee a third-party service implements HTTP preconditions.
The isolated TLS integration tests specifically reject HTTP 412 on PUT,
HTTP 403 on GET, and an otherwise authentic archive served under a different
content-addressed SHA-256 snapshot ID.
Retention, versioning and immutable storage must be configured at the
provider. The uploader does not auto-delete or prune remote objects.

## Limitations and verification

- The container uses one GCM nonce per snapshot and limits encrypted
  plaintext to under **32 GiB**. This is not yet a chunked multi-TiB
  backup format. Large datasets require a new versioned format.
- The native snapshot format does not currently preserve POSIX uid/gid,
  ACL, xattrs, special files or all original permissions; restore uses
  restrictive modes. There is no deduplication or incremental backup.
- HTTPS integration tests run against an **ephemeral local TLS server**,
  not a real storage provider; a provider-side signed-URL, encryption and
  independent restore drill is still required.
- `verify` checks GCM authenticity. It does **not** verify the complete
  application-level recovery of databases or hosted services.
- The legacy `securevault-ops` Restic and PITR tools remain source-only
  under the explicitly enabled `SECUREVAULT_LEGACY_RESTIC=ON` option.
  They are neither built nor installed by default.

The C++23 tests cover real encrypted-file and SQL-stream round trips,
wrong passwords, malicious/truncated data, wrong snapshot fingerprints,
key-file safety, HTTP/TLS PUT/GET, lost connectivity and fail-closed
publication. The HTTP test fixture rejects create-only upload conflicts
(HTTP 412), expired GET authorizations (HTTP 403), and valid ciphertext
under an incorrect SHA-256 identity. The SQL producer regression test
closes stdout but remains alive, confirming the coordinator enforces
a deadline and kills the stalled process. A separate C++23 CLI integration
test exercises the actual executable through init/create/list/verify/restore
and rejects invalid arguments and restore-target overwrite attempts.
Keep a known-good backup system in service until every
production acceptance gate in [RELEASE-READINESS.md](RELEASE-READINESS.md)
has been passed.
