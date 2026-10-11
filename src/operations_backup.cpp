#include "operations.hpp"
#include <array>
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
std::expected<void, std::string> save_success(const fs::path& path, const std::string& stamp) {
    std::ofstream out(path, std::ios::trunc);
    out << stamp << '\n';
    out.close();
    if (!out) return std::unexpected("Failed to publish success status");
    return {};
}
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
    fs::create_directories("/var/lib/securevault", ec);
    if (ec) return std::unexpected("Cannot create backup state directory");
    fs::permissions("/var/lib/securevault", fs::perms::owner_all, fs::perm_options::replace, ec);
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
         "/var/www", "/opt", "/etc", "/boot"}, false);
    if (!files || files->exit_code)
        return std::unexpected("Encrypted off-site file snapshot failed");
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
