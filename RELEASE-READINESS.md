# SecureVault release and disaster-recovery acceptance

**Status: native development candidate; production rollout blocked until the
external acceptance gates below are passed.** Do not replace an existing
working backup/DR solution yet. Completion of the source implementation
is not equivalent to proof of business continuity.

## Verified using isolated C++23 tests

- SVLT v2 AES-256-GCM and scrypt encryption, private secret files and
  authentication before publishing recovered files
- Content-addressed ciphertext SHA-256 IDs and strict recovery identity
- Streamed PostgreSQL/MariaDB logical dump adapter with producer exit
  validation and failure rollback; SQL not written to temporary plaintext
  files by the adapter
- HTTPS conditional PUT and GET using libcurl with TLS certificate
  verification, no redirect, 0600 URL files and fail-closed publication
- Real localhost TLS server fixture built with OpenSSL, with encryption
  roundtrip, received object equality and tampering refusal
- Local filesystem tests covering symlinks, hardlinks, path traversal,
  corrupt and truncated archives, duplicate destinations, and key safety

## Remaining gates before a production release

1. **Platform acceptance:** build and test the exact branch on a target
   macOS version and production Linux distribution/architecture. Use
   address/undefined behavior sanitizers and file-system stress tests.
2. **Object storage acceptance:** provision a real independent HTTPS object
   store, confirm conditional PUT cannot overwrite existing objects,
   simulate expired URLs, server 412/429/500, network loss, and verify a
   downloaded snapshot's SHA-256 and decrypted content on a separate host.
3. **End-to-end disaster recovery:** restore files, services, configuration,
   and databases to a genuinely isolated disposable environment. Confirm
   application behavior, not just successful decryption.
4. **Database reliability:** test `pg_dumpall` and `mariadb-dump` against
   isolated compatible database instances, verify roles, routines, triggers,
   events and nontransactional tables. Implement physical base backup,
   continuous WAL/binlog archival, correct retention and targeted PITR.
5. **Large data format:** ship a versioned, authenticated chunked container
   before promising backups beyond the current 32 GiB payload limit.
6. **Operational completeness:** implement retention/immutability policy,
   key recovery and rotation procedure, remote state monitoring and
   alerting, reproducible schedules and recovery drill automation.
7. **Security release:** review POSIX metadata requirements, hardlink and
   symlink semantics, concurrency and source mutation behavior; complete
   an independent security review including supply-chain dependencies.
8. **Restore documentation:** publish and practice a tested operator
   runbook with RPO/RTO measured using realistic data sizes and constraints.

## Operating boundaries

The native engine never starts production services, changes database
configuration or deletes existing backup repositories during its tests.
Its default CMake build does not include the historical Restic coordinator
or the legacy unencrypted archive engine.

**IMPORTANT:** The HTTPS transport uses a caller-supplied pre-signed
single-object URL. SecureVault cannot prove a service enforces
`If-None-Match: *` merely by sending that header. Confirm provider
semantics, object versioning and retention independently.

`SVLT v1` archives remain locally readable; new encrypted archives are
written as `SVLT v2` with a SHA-256 content-addressed filename. This
does not automatically convert old archives or guarantee their remote
object integrity.
