#include "operations.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <optional>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <regex>
#include <sstream>
#ifdef __unix__
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace securevault::ops {
namespace {
struct Log { std::uint64_t sequence{}; std::string name; std::uintmax_t size{}; };
std::string read_private_json(const fs::path& file) {
    std::ifstream in(file);
    if (!in) return {};
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
bool valid_id(std::string_view id) {
    return !id.empty() && id.size() <= 64 && std::isalnum(static_cast<unsigned char>(id.front())) &&
        std::all_of(id.begin(), id.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '_' || c == '-' || c == '.';
        });
}
std::expected<std::uint64_t, std::string> seq(const std::string& name, const std::string& prefix) {
    if (!name.starts_with(prefix + ".")) return std::unexpected("Unexpected binlog prefix");
    auto digits = name.substr(prefix.size() + 1);
    if (digits.size() < 6 || digits.size() > 12 || !std::all_of(digits.begin(), digits.end(), [](unsigned char c) {
        return std::isdigit(c) != 0;
    })) return std::unexpected("Invalid binlog sequence");
    try { return std::stoull(digits); } catch (...) { return std::unexpected("Invalid binlog number"); }
}
std::expected<std::string, std::string> query(const std::string& defaults, std::string_view sql) {
    auto result = execute({"mariadb", "--defaults-extra-file=" + defaults,
                           "--batch", "--skip-column-names", "--execute", std::string(sql)});
    if (!result || result->exit_code) return std::unexpected("Read-only MariaDB binlog inventory query failed");
    return result->out;
}
std::expected<std::pair<std::vector<Log>, std::string>, std::string>
inventory(const std::string& defaults, const std::string& prefix) {
    const auto listing = query(defaults, "SHOW BINARY LOGS");
    const auto master = query(defaults, "SHOW MASTER STATUS");
    if (!listing || !master) return std::unexpected("Cannot inspect MariaDB binlog inventory");
    std::vector<Log> rows;
    std::istringstream lines(*listing);
    std::string line;
    while (std::getline(lines, line)) {
        const auto tab = line.find('\t');
        if (tab == std::string::npos) return std::unexpected("Unexpected binlog inventory row");
        const auto name = line.substr(0, tab);
        const auto value = seq(name, prefix);
        if (!value) return std::unexpected(value.error());
        std::uintmax_t size = 0;
        try { size = std::stoull(line.substr(tab + 1)); } catch (...) {
            return std::unexpected("Invalid binlog byte count");
        }
        if (!size) return std::unexpected("Empty binlog in inventory");
        rows.push_back({*value, name, size});
    }
    if (rows.empty()) return std::unexpected("Binary logging unavailable or empty");
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        return a.sequence < b.sequence;
    });
    for (std::size_t i = 1; i < rows.size(); ++i)
        if (rows[i].sequence != rows[i - 1].sequence + 1)
            return std::unexpected("Server binlog inventory has a sequence gap");
    const auto active = master->substr(0, master->find_first_of("\t\r\n"));
    if (active != rows.back().name) return std::unexpected("Active binlog changed during inventory");
    rows.pop_back(); // do not ship an open binlog
    return std::pair{rows, active};
}
std::expected<std::uint64_t, std::string> fingerprint(const fs::path& path, std::uintmax_t expected_size) {
    std::error_code ec;
    if (!fs::is_regular_file(fs::symlink_status(path, ec)) || ec ||
        fs::file_size(path, ec) != expected_size)
        return std::unexpected("Closed binlog missing or length does not match server inventory");
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::unexpected("Closed binlog cannot be read");
    std::uint64_t hash = 14695981039346656037ULL;
    std::array<char, 65536> buffer{};
    std::uintmax_t count = 0;
    while (in) {
        in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto n = in.gcount();
        for (std::streamsize i = 0; i < n; ++i) {
            hash ^= static_cast<unsigned char>(buffer[static_cast<std::size_t>(i)]);
            hash *= 1099511628211ULL;
        }
        count += static_cast<std::uintmax_t>(n);
    }
    if (in.bad() || count != expected_size) return std::unexpected("Closed binlog changed during read");
    return hash; // content-change detector; Restic separately authenticates stored data.
}
std::expected<std::string, std::string> upload(const fs::path& path, const std::string& instance,
                                               const std::string& name) {
    auto result = execute({"restic", "backup", "--json",
        "--tag", "securevault", "--tag", "mariadb-binlog",
        "--tag", instance, "--tag", name, path.string()});
    if (!result || result->exit_code) return std::unexpected("Restic binlog upload failed");
    std::string snap;
    std::istringstream lines(result->out);
    std::string line;
    while (std::getline(lines, line)) {
        auto json = parse_json(line);
        if (!json || !json->isObject() || json->get("message_type", "").asString() != "summary")
            continue;
        if (!snap.empty()) return std::unexpected("Duplicate upload completion records");
        snap = json->get("snapshot_id", "").asString();
    }
    if (snap.size() != 64 || !std::all_of(snap.begin(), snap.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    })) return std::unexpected("Restic did not confirm a valid snapshot ID");
    return snap;
}
struct Lock {
    int fd = -1;
    explicit Lock(const fs::path& file) {
#ifdef __unix__
        fd = open(file.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
        if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB)) { close(fd); fd = -1; }
#endif
    }
    ~Lock() {
#ifdef __unix__
        if (fd >= 0) close(fd);
#endif
    }
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
};
std::expected<void, std::string> checkpoint(const fs::path& dest, const Json::Value& record) {
#ifdef __unix__
    auto pattern = (dest.parent_path() / ".securevault-checkpoint-XXXXXX").string();
    std::vector<char> chars(pattern.begin(), pattern.end());
    chars.push_back(0);
    int fd = mkstemp(chars.data());
    if (fd < 0) return std::unexpected("Cannot allocate state checkpoint");
    const std::string payload = Json::writeString(Json::StreamWriterBuilder{}, record);
    std::size_t written = 0;
    while (written < payload.size()) {
        auto n = write(fd, payload.data() + written, payload.size() - written);
        if (n <= 0) { close(fd); unlink(chars.data()); return std::unexpected("Cannot write checkpoint"); }
        written += static_cast<std::size_t>(n);
    }
    bool ok = fsync(fd) == 0 && close(fd) == 0;
    if (!ok || rename(chars.data(), dest.c_str()) != 0) {
        unlink(chars.data());
        return std::unexpected("Could not publish checkpoint");
    }
    const int dirfd = open(dest.parent_path().c_str(), O_RDONLY);
    if (dirfd >= 0) { fsync(dirfd); close(dirfd); }
    return {};
#else
    return std::unexpected("MariaDB binlog shipping requires POSIX");
#endif
}
} // namespace

Result binlog_ship(const fs::path& config_path, bool perform) {
#ifndef __unix__
    return std::unexpected("Binlog shipping currently requires Linux or macOS");
#else
    auto ready = remote_restic();
    if (!ready) return std::unexpected(ready.error());
    auto private_conf = private_file(config_path);
    if (!private_conf) return std::unexpected("Configuration file must be private");
    auto config = parse_json(read_private_json(config_path));
    if (!config || !config->isObject()) return std::unexpected("Invalid shipping configuration");
    const auto instance = (*config).get("instance_id", "").asString();
    const auto prefix = (*config).get("binlog_prefix", "").asString();
    const fs::path folder = (*config).get("binlog_dir", "").asString();
    const fs::path state_path = (*config).get("state_file", "").asString();
    const fs::path defaults = (*config).get("db_defaults_file", "").asString();
    if (!valid_id(instance) || !valid_id(prefix)) return std::unexpected("Invalid instance ID or binlog prefix");
    if (!folder.is_absolute() || !state_path.is_absolute() || !defaults.is_absolute())
        return std::unexpected("Shipping paths must be absolute");
    std::error_code ec;
    if (!fs::is_directory(folder, ec) || fs::is_symlink(fs::symlink_status(folder, ec)) ||
        !fs::is_directory(state_path.parent_path(), ec) ||
        fs::is_symlink(fs::symlink_status(state_path.parent_path(), ec)) ||
        state_path.string().starts_with(folder.string() + "/"))
        return std::unexpected("Unsafe binlog directory or checkpoint location");
    auto private_default = private_file(defaults);
    if (!private_default) return std::unexpected("MariaDB defaults file must be private");
    Lock lock(state_path.string() + ".lock");
    if (lock.fd < 0) return std::unexpected("Cannot acquire exclusive shipping lock");
    Json::Value state;
    if (fs::exists(state_path, ec)) {
        auto secure = private_file(state_path);
        if (!secure) return std::unexpected("State checkpoint is not private");
        auto json = parse_json(read_private_json(state_path));
        if (!json || !json->isObject()) return std::unexpected("Checkpoint is invalid");
        state = *json;
        if (state.get("instance_id", "").asString() != instance ||
            state.get("prefix", "").asString() != prefix || state.get("version", 0).asInt() != 1)
            return std::unexpected("Checkpoint belongs to another instance or version");
    } else {
        state["version"] = 1;
        state["instance_id"] = instance;
        state["prefix"] = prefix;
        state["last_sequence"] = Json::nullValue;
        state["last_snapshot"] = Json::nullValue;
    }
    std::optional<std::uint64_t> previous;
    if (!state["last_sequence"].isNull()) {
        if (!state["last_sequence"].isUInt64()) return std::unexpected("Corrupt checkpoint sequence");
        previous = state["last_sequence"].asUInt64();
    }
    auto inv = inventory(defaults.string(), prefix);
    if (!inv) return std::unexpected(inv.error());
    auto [closed, active] = std::move(*inv);
    auto active_seq = seq(active, prefix);
    if (!active_seq) return std::unexpected(active_seq.error());
    if (previous && *active_seq > *previous + 1 && closed.empty())
        return std::unexpected("Unshipped binlogs have disappeared");
    std::vector<Log> pending;
    for (const auto& log : closed) if (!previous || log.sequence > *previous) pending.push_back(log);
    if (previous && !pending.empty() && pending.front().sequence != *previous + 1)
        return std::unexpected("Gap between checkpoint and first unshipped binlog");
    if (previous && pending.empty() && *active_seq > *previous + 1)
        return std::unexpected("Unshipped binlogs were purged");
    Json::Value report;
    report["mode"] = perform ? "execute" : "dry-run";
    report["active_excluded"] = active;
    report["pending_closed_logs"] = Json::arrayValue;
    report["uploaded"] = Json::arrayValue;
    report["base_backup_verified"] = false;
    report["pitr_ready"] = false;
    for (const auto& log : pending) {
        report["pending_closed_logs"].append(log.name);
        const auto path = folder / log.name;
        auto first = fingerprint(path, log.size);
        if (!first) return std::unexpected(first.error());
        if (!perform) continue;
        auto snapshot = upload(path, instance, log.name);
        if (!snapshot) return std::unexpected(snapshot.error());
        auto after = fingerprint(path, log.size);
        if (!after || *first != *after) return std::unexpected("Binlog changed during upload; checkpoint unchanged");
        state["last_sequence"] = Json::UInt64(log.sequence);
        state["last_snapshot"] = *snapshot;
        auto saved = checkpoint(state_path, state);
        if (!saved) return std::unexpected(saved.error());
        Json::Value uploaded;
        uploaded["segment"] = log.name;
        uploaded["snapshot_id"] = *snapshot;
        report["uploaded"].append(uploaded);
    }
    report["last_successful_sequence"] = state["last_sequence"];
    return report;
#endif
}
} // namespace securevault::ops
