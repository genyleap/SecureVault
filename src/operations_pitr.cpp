#include "operations.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <regex>
#include <sstream>
#include <cstdlib>
#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

namespace securevault::ops {
namespace {
std::expected<std::string, std::string> target_utc(const std::string& input) {
    static const std::regex pattern(
        R"(^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(Z|([+-])([0-9]{2}):([0-9]{2}))$)");
    std::smatch match;
    if (!std::regex_match(input, match, pattern))
        return std::unexpected("Recovery time must use ISO 8601 with an explicit timezone");
    auto num = [&](std::size_t pos) { return std::stoi(match[pos].str()); };
    const int year = num(1), month = num(2), day = num(3);
    const int hour = num(4), minute = num(5), second = num(6);
    const int zone_hours = match[8].matched ? num(8) : 0;
    const int zone_minutes = match[9].matched ? num(9) : 0;
    if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 59 || zone_hours > 23 || zone_minutes > 59)
        return std::unexpected("Invalid recovery timestamp");
    std::tm tm{};
    tm.tm_year = year - 1900; tm.tm_mon = month - 1; tm.tm_mday = day;
    tm.tm_hour = hour; tm.tm_min = minute; tm.tm_sec = second;
#ifdef _WIN32
    const std::time_t raw = _mkgmtime(&tm);
#else
    const std::time_t raw = timegm(&tm);
#endif
    if (raw == static_cast<std::time_t>(-1)) return std::unexpected("Recovery timestamp conversion failed");
    std::tm roundtrip{};
#ifdef _WIN32
    gmtime_s(&roundtrip, &raw);
#else
    gmtime_r(&raw, &roundtrip);
#endif
    if (roundtrip.tm_year != year - 1900 || roundtrip.tm_mon != month - 1 ||
        roundtrip.tm_mday != day || roundtrip.tm_hour != hour ||
        roundtrip.tm_min != minute || roundtrip.tm_sec != second)
        return std::unexpected("Invalid calendar date");
    const int direction = match[7].matched && match[7].str() == "-" ? -1 : 1;
    const std::time_t utc = raw - direction * (zone_hours * 3600 + zone_minutes * 60);
    if (utc >= std::time(nullptr)) return std::unexpected("Recovery timestamp must be in the past");
    std::tm normalized{};
#ifdef _WIN32
    gmtime_s(&normalized, &utc);
#else
    gmtime_r(&utc, &normalized);
#endif
    std::ostringstream out;
    out << std::put_time(&normalized, "%Y-%m-%d %H:%M:%S+00");
    return out.str();
}
std::expected<fs::path, std::string> isolated_path(const fs::path& target) {
    if (!target.is_absolute() || target.filename().empty() ||
        target == target.root_path()) return std::unexpected("Absolute non-root directory required");
    for (const auto& item : target)
        if (item == "..") return std::unexpected("Parent traversal is forbidden");
    std::error_code ec;
    if (fs::exists(target, ec) || fs::is_symlink(fs::symlink_status(target, ec)))
        return std::unexpected("Recovery directory already exists");
    if (!fs::is_directory(target.parent_path(), ec) ||
        fs::is_symlink(fs::symlink_status(target.parent_path(), ec)))
        return std::unexpected("Recovery parent must be an existing non-symlink directory");
    const auto path = fs::weakly_canonical(target, ec);
    const auto allowed = fs::path("/srv/securevault-recovery");
    if (ec || path == allowed || path.string().starts_with(allowed.string() + "/") == false)
        return std::unexpected("Recovery directory must be beneath /srv/securevault-recovery");
    return path;
}
Json::Value report(bool inspected) {
    Json::Value obj;
    obj["checked"] = inspected;
    obj["local_prerequisites_met"] = false;
    obj["offsite_recovery_verified"] = false;
    obj["issues"] = Json::arrayValue;
    obj["warnings"] = Json::arrayValue;
    return obj;
}
std::string get(const Json::Value& v, const char* name) {
    return v.get(name, "").asString();
}
bool one_of(const std::string& value, std::initializer_list<const char*> values) {
    for (auto* candidate : values) if (value == candidate) return true;
    return false;
}
} // namespace

Result pitr_audit() {
    Json::Value result;
    result["schema"] = "securevault.pitr.readiness.v2";
    result["read_only"] = true;
    result["changes_applied"] = false;
    Json::Value pg = report(false), db = report(false);

    // Intentionally READ-ONLY, no ALTER SYSTEM, RESET, SWITCH, FLUSH or PURGE.
    const std::string query =
        "SELECT json_build_object("
        "'wal_level',current_setting('wal_level'),"
        "'archive_mode',current_setting('archive_mode'),"
        "'archive_target_configured',"
        "(current_setting('archive_command')<>'' OR"
        " current_setting('archive_library',true)<>''),"
        "'full_page_writes',current_setting('full_page_writes'),"
        "'archived_count',(SELECT archived_count FROM pg_stat_archiver),"
        "'failed_count',(SELECT failed_count FROM pg_stat_archiver))::text";
    std::vector<std::string> command = {"psql", "-X", "-A", "-t",
                                       "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", query};
#if defined(__linux__) || defined(__APPLE__)
    if (geteuid() == 0 && has_tool("runuser"))
        command.insert(command.begin(), {"runuser", "-u", "postgres", "--"});
#endif
    auto query_result = execute(command);
    if (!query_result || query_result->exit_code) {
        pg["issues"].append("PostgreSQL read-only inspection failed or credentials missing");
    } else {
        auto parsed = parse_json(query_result->out);
        if (!parsed || !parsed->isObject()) {
            pg["issues"].append("PostgreSQL returned invalid configuration JSON");
        } else {
            pg["checked"] = true;
            pg["observed"] = *parsed;
            if (!one_of(get(*parsed, "wal_level"), {"replica", "logical"}))
                pg["issues"].append("wal_level must be replica or logical");
            if (!one_of(get(*parsed, "archive_mode"), {"on", "always"}))
                pg["issues"].append("archive_mode is disabled");
            if (!(*parsed)["archive_target_configured"].asBool())
                pg["issues"].append("WAL archive target is not configured");
            if (get(*parsed, "full_page_writes") != "on")
                pg["issues"].append("full_page_writes is disabled");
            if ((*parsed).get("archived_count", 0).asInt64() == 0)
                pg["warnings"].append("No observed WAL archive successes");
            if ((*parsed).get("failed_count", 0).asInt64() != 0)
                pg["warnings"].append("WAL archiver has recorded failures");
        }
    }
    if (!has_tool("pgbackrest")) pg["issues"].append("pgBackRest executable missing");
    pg["warnings"].append("Local settings cannot verify remote WAL continuity or restore ability");
    pg["local_prerequisites_met"] = pg["checked"].asBool() && pg["issues"].empty();

    auto maria = execute({"mariadb", "--batch", "--skip-column-names", "--execute",
        "SHOW GLOBAL VARIABLES WHERE Variable_name IN "
        "('log_bin','binlog_format','server_id','expire_logs_days','binlog_expire_logs_seconds')"});
    if (!maria || maria->exit_code) {
        db["issues"].append("MariaDB read-only inspection failed or credentials missing");
    } else {
        Json::Value observed;
        std::istringstream lines(maria->out);
        std::string line;
        while (std::getline(lines, line)) {
            auto tab = line.find('\t');
            if (tab == std::string::npos) continue;
            observed[line.substr(0, tab)] = line.substr(tab + 1);
        }
        if (observed.empty()) {
            db["issues"].append("MariaDB returned no settings");
        } else {
            db["checked"] = true;
            db["observed"] = observed;
            if (!one_of(get(observed, "log_bin"), {"ON", "1"}))
                db["issues"].append("MariaDB binary logging is disabled");
            if (get(observed, "binlog_format") != "ROW")
                db["warnings"].append("ROW binlog format is recommended");
            try {
                if (std::stoi(get(observed, "server_id")) < 1)
                    db["issues"].append("MariaDB server_id is disabled");
            } catch (...) { db["issues"].append("MariaDB server_id is invalid"); }
        }
    }
    if (!has_tool("mariadb-backup")) db["issues"].append("mariadb-backup executable missing");
    if (!has_tool("mariadb-binlog") && !has_tool("mysqlbinlog"))
        db["issues"].append("MariaDB binlog replay tool missing");
    db["warnings"].append("Local settings cannot verify remote binlog continuity or base backup");
    db["local_prerequisites_met"] = db["checked"].asBool() && db["issues"].empty();
    result["postgresql"] = pg;
    result["mariadb"] = db;
    return result;
}

Result pitr_plan_pg(const std::string& stanza, const std::string& time, const fs::path& dest) {
    static const std::regex safe("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$");
    if (!std::regex_match(stanza, safe)) return std::unexpected("Invalid pgBackRest stanza name");
    auto normalized = target_utc(time);
    if (!normalized) return std::unexpected(normalized.error());
    auto target = isolated_path(dest);
    if (!target) return std::unexpected(target.error());
    Json::Value r;
    r["engine"] = "postgresql"; r["plan_only"] = true; r["executed"] = false;
    r["restore_target_utc"] = *normalized; r["isolated_data_directory"] = target->string();
    r["preconditions"].append("Use a dedicated isolated recovery host with PostgreSQL stopped");
    r["preconditions"].append("Verify compatible pgBackRest base backup and continuous WAL archive");
    r["preconditions"].append("Check repository credentials and matching PostgreSQL versions");
    r["preconditions"].append("Start recovered PostgreSQL only on an isolated socket or port");
    const std::vector<std::string> argv = {
        "pgbackrest", "--stanza=" + stanza, "--pg1-path=" + target->string(),
        "--type=time", "--target=" + *normalized, "--target-action=promote", "restore"
    };
    for (const auto& arg : argv) r["review_only_command_argv"].append(arg);
    return r;
}
Result pitr_plan_mariadb(const std::string& time, const fs::path& dest) {
    auto normalized = target_utc(time);
    if (!normalized) return std::unexpected(normalized.error());
    auto target = isolated_path(dest);
    if (!target) return std::unexpected(target.error());
    Json::Value r;
    r["engine"] = "mariadb"; r["plan_only"] = true; r["executed"] = false;
    r["restore_target_utc"] = *normalized; r["isolated_data_directory"] = target->string();
    for (const auto* step : {
        "Select a compatible mariadb-backup physical base backup from before the target time",
        "Validate base backup metadata and binlog start positions or GTID",
        "Verify an uninterrupted off-host binlog chain through target time",
        "Prepare a writable copy of base backup, never the sole retained copy",
        "Restore into a new directory on an isolated stopped MariaDB instance",
        "Replay verified binlog events only to the reviewed GTID/position/time boundary",
        "Check restored data against application invariants before promotion",
    }) r["required_manual_steps"].append(step);
    r["note"] = "Time-based binlog replay is not necessarily transaction-boundary exact.";
    return r;
}
} // namespace securevault::ops
