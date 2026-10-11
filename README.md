# SecureVault

**Native C++23 encrypted backup engine**, with no dependency on the Restic executable,
Python, or shell scripts for native snapshot creation, authentication and recovery.

The new primary command is \`securevault-vault\`. It uses a versioned SecureVault
container format (\`SVLT v1\`) implemented in C++23, using **OpenSSL 3 primitives**:
\`AES-256-GCM\` authenticated encryption, \`scrypt\` password-based key derivation
(32768/N, r=8, p=1), fresh 128-bit salt and 96-bit nonce for every snapshot.
This uses an established crypto library; SecureVault does **not** invent its own cipher.

## Build and test

Required: CMake >=3.26, a C++23 compiler and OpenSSL development files.
The original tar/database core additionally requires libarchive, JSONCPP,
libcurl, zlib and optionally libssh.

On macOS, install prerequisites with Homebrew (\`openssl@3\`,
\`cmake\`, \`ninja\`, plus packages required for the original core):

\`\`\`bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ \
  -DSECUREVAULT_BUILD_CORE=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
\`\`\`

The native vault is enabled by default, and the historical
\`SECUREVAULT_LEGACY_RESTIC\` compatibility build option defaults to **OFF**.
**No Restic binary needs to be installed.** This option retains a deprecated
source migration path temporarily, not a runtime requirement for the native
vault. It must not be enabled for production.

## Create, list, authenticate and restore snapshots

Initialize an empty private directory, and create a password file protected
by mode \`0600\`. Do not save the key file inside the backed-up tree or vault.
Use a strong randomly generated password held independently of the archives.

\`\`\`bash
securevault-vault init --repo /absolute/private/vault
securevault-vault create --repo /absolute/private/vault \
  --source /absolute/test-fixtures --password-file /absolute/keyfile
securevault-vault list --repo /absolute/private/vault
securevault-vault verify --snapshot /absolute/private/vault/<snapshot-id>.svlt \
  --password-file /absolute/keyfile
securevault-vault restore --snapshot /absolute/private/vault/<snapshot-id>.svlt \
  --target /absolute/new-recovery-folder --password-file /absolute/keyfile
\`\`\`

Restore targets must be new and cannot replace existing directories. Files
are restored with mode \`0600\` and directories with \`0700\`. Regular files,
empty directories and safe relative symlinks are supported. Unknown objects,
hardlinks, escaping symlinks and duplicate paths are rejected. Snapshot
creation uses a private temporary file and atomic no-overwrite publication.
Restoration authenticates the **entire** encrypted archive before writing the
recovery tree, authenticates it again during extraction and publishes only
after successful verification.

\`verify\` checks the authenticated encryption tag, not a complete application
restore. To establish recoverability, run a full \`restore\` into a disposable
location and inspect application semantics as well.

## Important limits

- **Not ready for production off-site disaster recovery.** The new backend
  currently stores encrypted snapshots in a local/private directory. Its
  independent off-host transport (e.g. SFTP or object storage), retention
  policies, scheduling, monitoring and verified failure recovery are still to
  be implemented and tested. A local encrypted copy is not an off-site backup.
- The v1 container is streaming, but each snapshot is limited to under
  **32 GiB of encrypted payload** because it uses one AES-GCM nonce per
  snapshot. Larger datasets require a future independently authenticated
  chunked container format; do not split encrypted snapshots manually.
- This first native milestone does not deduplicate, compress, preserve
  all POSIX ownership/ACL/xattrs or implement incremental snapshots.
- PostgreSQL and MariaDB backups need a separately validated coordination
  layer and isolated recovery tests. The original C++ tar/SQL engine is
  available separately, but its unencrypted outputs should not be mistaken
  for new native encrypted snapshots.
- The deprecated Restic operations are **not built or installed by default**;
  they still exist in the repository during migration. Do not deploy or
  schedule that legacy path. The new native vault has no Restic dependency.
- Do not point development tests at live data or production repositories.
  CTest uses only disposable synthetic files and directories.

## Security testing

\`tests/vault_tests.cpp\` performs real AES-256-GCM/scrypt roundtrips without
mocking a third-party backup process. It covers binary data, subfolders,
empty directories, safe symlinks, bad passwords, insecure keys, tampering,
truncation, hardlinks, unsafe paths, and accidental recursive self-backup.

## Existing documentation

- [DISASTER-RECOVERY.md](DISASTER-RECOVERY.md) describes the historical
  operational setup and recovery acceptance criteria; references to Restic
  there are **legacy** and not part of the native vault.
- [PITR-READINESS.md](PITR-READINESS.md) describes the separate experimental
  point-in-time-recovery planner and legacy log shipping module, not complete
  native PITR support.

**Production safety:** Running CMake/CTest never installs/starts a backup
scheduler, changes DB configuration, or touches running services. Keep an
independently verified existing backup system until the native replacement
passes complete off-site restore acceptance testing.
