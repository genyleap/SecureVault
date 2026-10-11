#include "operations.hpp"
#include <array>
#include <cerrno>
#include <cstdlib>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#if defined(__linux__)
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace securevault::ops {
namespace {
#if defined(__linux__)
std::string generation_tag() {
    const auto now = std::time(nullptr);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    std::ostringstream out;
    out << std::put_time(&utc, "%Y%m%dT%H%M%SZ");
    return out.str();
}
std::expected<void, std::string> repository_exists() {
    auto snapshots = execute({"restic", "snapshots", "--latest", "1"});
    if (!snapshots || snapshots->exit_code)
        return std::unexpected("Off-site Restic repository is missing or inaccessible");
    return {};
}
// A private, fully-flushed temporary file is used for both the encrypted
// remote completion marker and the local success checkpoint.
std::expected<fs::path, std::string> write_private_temp(
    const fs::path& directory, const std::string& prefix,
    const std::string& contents) {
    const std::string pattern = (directory / (prefix + "XXXXXX")).string();
    std::vector<char> buffer(pattern.begin(), pattern.end());
    buffer.push_back('\0');
    const int fd = mkstemp(buffer.data());
    if (fd < 0) return std::unexpected("Cannot allocate private completion record");
    const fs::path file = buffer.data();
    std::size_t written = 0;
    bool ok = true;
    while (written < contents.size()) {
        const ssize_t n = write(fd, contents.data() + written, contents.size() - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        written += static_cast<std::size_t>(n);
    }
    const bool synced = ok && fsync(fd) == 0;
    const bool closed = close(fd) == 0;
    if (!synced || !closed) {
        unlink(file.c_str());
        return std::unexpected("Cannot safely flush completion record");
    }
    return file;
}
std::expected<void, std::string> commit_generation(const std::string& stamp) {
    Json::Value manifest;
    manifest["schema"] = "securevault.restic.generation.v1";
    manifest["generation"] = stamp;
    manifest["files"] = true;
    manifest["postgresql"] = true;
    manifest["mariadb"] = true;
    manifest["transactionally_consistent"] = false;
    Json::StreamWriterBuilder writer;
    auto file = write_private_temp("/var/lib/securevault", ".generation-",
                                   Json::writeString(writer, manifest));
    if (!file) return std::unexpected(file.error());
    const auto uploaded = execute(
        {"restic", "backup", "--tag", "securevault",
         "--tag", "generation-committed", "--tag", stamp, file->string()},
        false, std::chrono::hours{2});
    unlink(file->c_str());
    if (!uploaded || uploaded->exit_code != 0)
        return std::unexpected("Restic remote generation commit failed");
    return {};
}
std::expected<void, std::string> save_success(const fs::path& path,
                                              const std::string& stamp) {
    auto file = write_private_temp(path.parent_path(), ".last-success-",
                                   stamp + "\n");
    if (!file) return std::unexpected(file.error());
    if (rename(file->c_str(), path.c_str()) != 0) {
        unlink(file->c_str());
        return std::unexpected("Cannot atomically publish local success marker");
    }
    const int dir_fd = open(path.parent_path().c_str(), O_RDONLY);
    if (dir_fd < 0) return std::unexpected("Cannot open success state directory");
    const bool synced = fsync(dir_fd) == 0;
    const bool closed = close(dir_fd) == 0;
    if (!synced || !closed)
        return std::unexpected("Cannot durably sync local success marker");
    return {};
}
#endif // __linux__: helpers used only by the Linux backup coordinator
} // namespace
Result restic_backup() {
#ifndef __linux__
    return std::unexpected("Encrypted logical DB backup coordinator is Linux-only");
#else
    if (geteuid() != 0) return std::unexpected("Root required for system snapshot");
    auto safe = remote_restic();
    if (!safe) return std::unexpected(safe.error());
    if (!has_tool("flock") || !has_tool("runuser") || !has_tool("pg_dumpall") ||
        !has_tool("mariadb-dump"))
        return std::unexpected("Required backup or database tools missing");
    for (const char* dir : {"/var/www", "/opt", "/etc", "/boot"})
        if (!fs::is_directory(dir)) return std::unexpected("Required backup directory missing");
    std::error_code ec;
    const fs::path state_dir = "/var/lib/securevault";
    fs::create_directories(state_dir, ec);
    if (ec) return std::unexpected("Cannot create backup state directory");
    const auto status = fs::symlink_status(state_dir, ec);
    if (ec || fs::is_symlink(status) || !fs::is_directory(status))
        return std::unexpected("Backup state directory must be a real directory");
    fs::permissions(state_dir, fs::perms::owner_all, fs::perm_options::replace, ec);
    if (ec) return std::unexpected("Cannot secure backup state directory");
    auto repo = repository_exists();
    if (!repo) return std::unexpected(repo.error());
    const int fd = open("/run/securevault-ops.lock", O_WRONLY | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0) return std::unexpected("Cannot create backup lock");
    struct Guard {
        int fd;
        ~Guard() { flock(fd, LOCK_UN); close(fd); }
    } guard{fd};
    if (flock(fd, LOCK_EX | LOCK_NB)) return std::unexpected("Another backup job holds the lock");
    const std::string stamp = generation_tag();
    const auto postgres = pipe_processes(
        {"runuser", "-u", "postgres", "--", "pg_dumpall"},
        {"restic", "backup", "--stdin", "--stdin-filename", "postgresql-all.sql",
         "--tag", "securevault", "--tag", "postgresql", "--tag", stamp});
    if (!postgres) return std::unexpected(postgres.error());
    const auto maria = pipe_processes(
        {"mariadb-dump", "--all-databases", "--single-transaction", "--quick",
         "--routines", "--events", "--triggers"},
        {"restic", "backup", "--stdin", "--stdin-filename", "mariadb-all.sql",
         "--tag", "securevault", "--tag", "mariadb", "--tag", stamp});
    if (!maria) return std::unexpected(maria.error());
    const auto files = execute(
        {"restic", "backup", "--one-file-system", "--exclude-caches",
         "--tag", "securevault", "--tag", "files", "--tag", stamp,
         "/var/www", "/opt", "/etc", "/boot"}, false, std::chrono::hours{12});
    if (!files || files->exit_code)
        return std::unexpected("Encrypted off-site file snapshot failed");

    // Three Restic snapshots may exist after a failed producer;
    // only this final encrypted marker commits the generation.
    const auto committed = commit_generation(stamp);
    if (!committed) return std::unexpected(committed.error());
    auto saved = save_success("/var/lib/securevault/last_success", stamp);
    if (!saved) return std::unexpected(saved.error());
    Json::Value result;
    result["generation"] = stamp;
    result["status"] = "COMPLETE";
    result["encrypted_offsite"] = true;
    result["cross_service_transactional"] = false;
    return result;
#endif
}
} // namespace securevault::ops
