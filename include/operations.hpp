#pragma once
#include <chrono>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
#include <json/json.h>

namespace securevault::ops {
namespace fs = std::filesystem;
struct ProcessResult { int exit_code{}; std::string out; };
using Result = std::expected<Json::Value, std::string>;

std::expected<ProcessResult, std::string> execute(
    const std::vector<std::string>& args, bool capture = true,
    std::chrono::seconds timeout = std::chrono::seconds{300});
std::expected<void, std::string> pipe_processes(
    const std::vector<std::string>& producer, const std::vector<std::string>& consumer,
    std::chrono::seconds timeout = std::chrono::hours{12});
bool has_tool(const std::string& name);
std::expected<void, std::string> private_file(const fs::path& path);
std::expected<void, std::string> remote_restic();
std::expected<Json::Value, std::string> parse_json(std::string_view text);
Json::Value error_json(const std::string& message);

Result restic_list();
Result restic_generations();
// Internal integration seam: production always performs remote_restic()
// before calling this inspector. The test provides a private fixture directory.
Result inspect_restic_generations(const Json::Value& inventory,
                                  const fs::path& expected_marker_directory);
Result restic_generation_snapshot_ids(const std::string& generation);
Result restic_check();
Result restic_restore(const std::string& id, const std::string& kind,
                      const fs::path& destination, bool allow_plaintext);
Result restic_backup();

Result pitr_audit();
Result pitr_plan_pg(const std::string& stanza, const std::string& time, const fs::path& target);
Result pitr_plan_mariadb(const std::string& time, const fs::path& target);

Result binlog_ship(const fs::path& config_path, bool upload);
int entry(int argc, char** argv);
}
