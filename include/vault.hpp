#pragma once
#include <chrono>
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace securevault::vault {
namespace fs = std::filesystem;
using Status = std::expected<void, std::string>;
using Snapshot = std::expected<fs::path, std::string>;

// SVLT v1: authenticated, versioned, independent encrypted archive.
// No external backup executable or scripting runtime is required.
Status initialize(const fs::path& repository);
Snapshot create(const fs::path& repository, const fs::path& source,
                const fs::path& password_file);
// Encrypt PostgreSQL/MariaDB logical dump stdout directly into a snapshot;
// no intermediate plaintext SQL file and no Restic execution.
Snapshot create_logical_dump(const fs::path& repository,
                             const fs::path& password_file,
                             const std::string& database,
                             const fs::path& executable = {},
                             std::chrono::seconds timeout = std::chrono::hours{12});
// A generation commits only after file, PostgreSQL and MariaDB snapshots
// are complete; the returned encrypted snapshot is a manifest of their IDs.
Snapshot create_generation(const fs::path& repository, const fs::path& source,
                           const fs::path& password_file,
                           const fs::path& pg_executable = {},
                           const fs::path& mariadb_executable = {});
Status verify_generation(const fs::path& repository,
                         const fs::path& manifest_snapshot,
                         const fs::path& password_file);
Status verify(const fs::path& archive, const fs::path& password_file);
Status restore(const fs::path& archive, const fs::path& target,
               const fs::path& password_file);
std::expected<std::vector<fs::path>, std::string> list(const fs::path& repository);
// SHA-256 of the encrypted snapshot bytes; new snapshot filenames are content addressed.
std::expected<std::string, std::string> ciphertext_digest(const fs::path& archive);

// HTTPS transfer uses a private (0600) file containing a pre-authorized,
// single-object HTTPS URL. Upload requires conditional create support on
// the remote endpoint (If-None-Match: *). No shell or Restic subprocesses.
Status upload_https(const fs::path& archive, const fs::path& password_file,
                    const fs::path& url_file, const fs::path& ca_bundle = {});
Snapshot download_https(const fs::path& repository,
                        const std::string& snapshot_id,
                        const fs::path& password_file,
                        const fs::path& url_file, const fs::path& ca_bundle = {});
}
