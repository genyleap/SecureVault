#include "operations.hpp"
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace securevault::ops;
namespace {
int checks = 0;
int failures = 0;
void check(bool value, const std::string& message) {
    ++checks;
    if (!value) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}
void file(const fs::path& path, std::string_view text) {
    std::ofstream f(path);
    f << text;
    if (!f) throw std::runtime_error("Test fixture write failed");
}
struct Temp {
    fs::path dir;
    Temp() {
        auto pattern = (fs::temp_directory_path() / "securevault-cpp-XXXXXX").string();
        std::vector<char> b(pattern.begin(), pattern.end());
        b.push_back(0);
        if (!mkdtemp(b.data())) throw std::runtime_error("Cannot create fixture dir");
        dir = b.data();
    }
    ~Temp() { std::error_code ec; fs::remove_all(dir, ec); }
};
void install_mock(const fs::path& bin, const fs::path& self, const std::string& name) {
    fs::create_symlink(self, bin / name);
}
int mocked(int argc, char** argv) {
    const auto name = fs::path(argv[0]).filename().string();
    std::string action = argc > 1 ? argv[1] : "";
    if (name == "restic") {
        if (action == "stall") { sleep(3); return 0; }
        const std::string a(64, 'a'), b(64, 'b'), c(64, 'c'), d(64, 'd');
        if (action == "snapshots") {
            std::cout << "["
                "{\"id\":\"" << a << "\",\"tags\":[\"securevault\",\"files\",\"20261011T090000Z\"]},"
                "{\"id\":\"" << b << "\",\"tags\":[\"securevault\",\"postgresql\",\"20261011T090000Z\"]}"
                << (std::getenv("SV_MOCK_MISSING_MARIA") ? "" :
                    ",{\"id\":\"" + c + "\",\"tags\":[\"securevault\",\"mariadb\",\"20261011T090000Z\"]}")
                << (std::getenv("SV_MOCK_MISSING_COMMIT") ? "" :
                    ",{\"id\":\"" + d + "\",\"tags\":[\"securevault\",\"generation-committed\"," +
                    (std::getenv("SV_MOCK_MIXED_COMMIT_KIND") ? "\"files\"," : "") +
                    "\"20261011T090000Z\"]}")
                << "]\n";
        } else if (action == "restore") {
            std::string target;
            for (int i = 2; i + 1 < argc; ++i)
                if (std::string_view(argv[i]) == "--target") target = argv[i + 1];
            if (target.empty()) return 42;
            if (argv[2] == b) {
                file(fs::path(target) / "postgresql-all.sql", "SELECT 1;\n");
                if (std::getenv("SV_MOCK_EXTRA_SQL"))
                    file(fs::path(target) / "unexpected.sql", "SELECT 2;\n");
            } else {
                const auto dir = fs::path(target) / "var" / "www";
                fs::create_directories(dir);
                file(dir / "index.txt", "restored contents\n");
                if (std::getenv("SV_MOCK_EVIL_SYMLINK"))
                    fs::create_symlink("/etc/passwd", fs::path(target) / "evil");
                if (std::getenv("SV_MOCK_SAFE_SYMLINK"))
                    fs::create_symlink("index.txt", dir / "safe-link");
                if (std::getenv("SV_MOCK_SPECIAL_FIFO"))
                    if (mkfifo((fs::path(target) / "unsafe-fifo").c_str(), 0600) != 0) return 44;
                if (std::getenv("SV_MOCK_HARDLINK"))
                    fs::create_hard_link(dir / "index.txt", dir / "hardlinked.txt");
            }
            if (const char* raced = std::getenv("SV_MOCK_RACE_DEST")) {
                fs::create_directory(raced);
                file(fs::path(raced) / "sentinel", "must remain");
            }
            if (std::getenv("SV_MOCK_FAIL_RESTORE")) return 35;
        } else if (action == "backup") {
            if (std::getenv("SV_MOCK_UPLOAD_FAIL")) return 23;
            if (std::getenv("SV_MOCK_BINLOG_MUTATE") && argc >= 3) {
                std::ofstream changed(argv[argc - 1], std::ios::binary | std::ios::trunc);
                changed << "FAIL"; // Same length, different content.
            }
            std::cout << "{\"message_type\":\"summary\",\"snapshot_id\":\"" << a << "\"}\n";
        } else if (action == "check") {
            if (std::getenv("SV_MOCK_CHECK_FAIL")) return 23;
        } else return 42;
        return 0;
    }
    if (name == "mariadb") {
        for (int i = 1; i < argc; ++i) {
            const std::string argument = argv[i];
            if (argument == "SHOW BINARY LOGS") {
                if (std::getenv("SV_MOCK_GAP_BINLOGS"))
                    std::cout << "mysql-bin.000001\t4\nmysql-bin.000003\t4\n";
                else if (std::getenv("SV_MOCK_MORE_BINLOGS"))
                    std::cout << "mysql-bin.000001\t4\nmysql-bin.000002\t4\nmysql-bin.000003\t4\n";
                else
                    std::cout << "mysql-bin.000001\t4\nmysql-bin.000002\t4\n";
                return 0;
            }
            if (argument == "SHOW MASTER STATUS") {
                std::cout << ((std::getenv("SV_MOCK_MORE_BINLOGS") ||
                               std::getenv("SV_MOCK_GAP_BINLOGS")) ?
                              "mysql-bin.000003\t4\n" : "mysql-bin.000002\t4\n");
                return 0;
            }
            if (argument.find("SHOW GLOBAL VARIABLES") != std::string::npos) {
                std::cout << "log_bin\tON\nbinlog_format\tROW\nserver_id\t1\n";
                return 0;
            }
        }
        return 42;
    }
    if (name == "psql") {
        std::cout << "{\"wal_level\":\"replica\",\"archive_mode\":\"on\","
                     "\"archive_target_configured\":true,\"full_page_writes\":\"on\","
                     "\"archived_count\":12,\"failed_count\":0}\n";
        return 0;
    }
    return 42;
}
} // namespace

int main(int argc, char** argv) {
    const auto called = fs::path(argv[0]).filename().string();
    if (called != "securevault-native-tests") return mocked(argc, argv);
    Temp temp;
    const auto self = fs::canonical(argv[0]);
    const auto bin = temp.dir / "bin";
    fs::create_directory(bin);
    for (const char* name : {"restic", "mariadb", "psql", "pgbackrest", "mariadb-backup", "mariadb-binlog"})
        install_mock(bin, self, name);
    const auto original = std::getenv("PATH") ? std::getenv("PATH") : "";
    const auto newpath = bin.string() + ":" + original;
    setenv("PATH", newpath.c_str(), 1);
    setenv("RESTIC_REPOSITORY", "s3:dummy-test-bucket", 1);
    auto pass = temp.dir / "restic-password";
    file(pass, "test-only\n");
    chmod(pass.c_str(), 0600);
    setenv("RESTIC_PASSWORD_FILE", pass.c_str(), 1);

    auto inventory = restic_list();
    check(inventory && inventory->size() == 4,
          "Restic inventory recognizes three data snapshots and a commit marker");
    auto groups = restic_generations();
    check(groups && groups->size() == 1 &&
          (*groups)[0]["status"].asString() == "COMPLETE" &&
          (*groups)[0]["committed"].asBool(),
          "Generation is complete only with the final encrypted commit marker");
    setenv("SV_MOCK_MISSING_COMMIT", "1", 1);
    auto uncommitted = restic_generations();
    check(uncommitted && uncommitted->size() == 1 &&
          (*uncommitted)[0]["status"].asString() == "INCOMPLETE" &&
          !(*uncommitted)[0]["committed"].asBool(),
          "Three snapshot kinds without a commit marker remain INCOMPLETE");
    unsetenv("SV_MOCK_MISSING_COMMIT");
    setenv("SV_MOCK_MIXED_COMMIT_KIND", "1", 1);
    auto invalid_marker = restic_generations();
    check(invalid_marker && invalid_marker->size() == 1 &&
          (*invalid_marker)[0]["status"].asString() == "INCOMPLETE",
          "Commit marker with mixed backup kinds is rejected");
    unsetenv("SV_MOCK_MIXED_COMMIT_KIND");
    setenv("SV_MOCK_MISSING_MARIA", "1", 1);
    auto incomplete = restic_generations();
    check(incomplete && (*incomplete)[0]["status"].asString() == "INCOMPLETE",
          "A missing database snapshot makes the generation incomplete");
    unsetenv("SV_MOCK_MISSING_MARIA");
    auto integrity = restic_check();
    check(integrity && (*integrity)["checked"].asBool(), "Restic integrity check");
    // Process deadlines must work with and without captured stdout.
    auto stalled_output = execute({(bin / "restic").string(), "stall"},
                                  true, std::chrono::seconds{1});
    check(!stalled_output && stalled_output.error() == "External command timed out",
          "Captured external process cannot hang indefinitely");
    auto stalled_silent = execute({(bin / "restic").string(), "stall"},
                                  false, std::chrono::seconds{1});
    check(!stalled_silent && stalled_silent.error() == "External command timed out",
          "Silent external process cannot hang indefinitely");
    auto stalled_stream = pipe_processes({(bin / "restic").string(), "stall"},
        {(bin / "restic").string(), "check"}, std::chrono::seconds{1});
    check(!stalled_stream && stalled_stream.error().find("timed out") != std::string::npos,
          "Streaming database backup cannot hang indefinitely");
    setenv("SV_MOCK_CHECK_FAIL", "1", 1);
    auto failed_stream = pipe_processes({(bin / "restic").string(), "stall"},
        {(bin / "restic").string(), "check"}, std::chrono::seconds{3});
    check(!failed_stream && failed_stream.error().find("failed") != std::string::npos,
          "Streaming stops the producer after consumer failure");
    check(!restic_check(), "Restic data-check failure is fatal");
    unsetenv("SV_MOCK_CHECK_FAIL");
    const auto target = temp.dir / "restored";
    auto recovery = restic_restore(std::string(64, 'a'), "files", target, false);
    check(recovery && fs::exists(target / "var" / "www" / "index.txt"), "Encrypted file restore succeeds");
    auto refuse = restic_restore(std::string(64, 'a'), "files", target, false);
    check(!refuse, "Never overwrite an existing recovery directory");
    auto sql_denied = restic_restore(std::string(64, 'b'), "postgresql", temp.dir / "sql", false);
    check(!sql_denied, "SQL plaintext export requires opt-in");
    auto sql_allowed = restic_restore(std::string(64, 'b'), "postgresql", temp.dir / "sql", true);
    check(sql_allowed && fs::exists(temp.dir / "sql/postgresql-all.sql"), "Opt-in SQL export");
    setenv("SV_MOCK_EVIL_SYMLINK", "1", 1);
    auto evil = restic_restore(std::string(64, 'a'), "files", temp.dir / "evil-dest", false);
    check(!evil && !fs::exists(temp.dir / "evil-dest"), "Reject link escaping staging root");
    unsetenv("SV_MOCK_EVIL_SYMLINK");

    setenv("SV_MOCK_SAFE_SYMLINK", "1", 1);
    const auto safe_link_target = temp.dir / "safe-symlink-dest";
    auto safe_link = restic_restore(std::string(64, 'a'), "files", safe_link_target, false);
    if (!safe_link) std::cerr << "Safe symlink restore error: " << safe_link.error() << '\n';
    check(safe_link && fs::is_symlink(safe_link_target / "var" / "www" / "safe-link"),
          "Relative in-root symlinks remain supported");

    // Simulates macOS /var -> /private/var: the staged path contains an
    // existing symlink in an ANCESTOR, not in the recovered archive.
    // Canonicalizing only the staging root used to reject this incorrectly.
    const auto actual_parent = temp.dir / "actual-parent" / "inside";
    fs::create_directories(actual_parent);
    const auto aliased_parent = temp.dir / "aliased-parent";
    fs::create_symlink(temp.dir / "actual-parent", aliased_parent);
    const auto aliased_target = aliased_parent / "inside" / "restored";
    auto aliased_restore = restic_restore(std::string(64, 'a'), "files",
                                          aliased_target, false);
    if (!aliased_restore)
        std::cerr << "Symlinked-ancestor restore error: " << aliased_restore.error() << '\n';
    check(aliased_restore && fs::is_symlink(aliased_target / "var" / "www" / "safe-link"),
          "Safe relative symlinks work with canonicalization aliases in parent paths");
    unsetenv("SV_MOCK_SAFE_SYMLINK");

    setenv("SV_MOCK_SPECIAL_FIFO", "1", 1);
    auto fifo = restic_restore(std::string(64, 'a'), "files", temp.dir / "fifo-dest", false);
    check(!fifo && !fs::exists(temp.dir / "fifo-dest"),
          "Reject special FIFO device-like entries before publication");
    unsetenv("SV_MOCK_SPECIAL_FIFO");

    setenv("SV_MOCK_HARDLINK", "1", 1);
    auto hardlink = restic_restore(std::string(64, 'a'), "files", temp.dir / "hardlink-dest", false);
    check(!hardlink && !fs::exists(temp.dir / "hardlink-dest"),
          "Reject hardlinked entries before publication");
    unsetenv("SV_MOCK_HARDLINK");

    setenv("SV_MOCK_FAIL_RESTORE", "1", 1);
    auto partial = restic_restore(std::string(64, 'a'), "files", temp.dir / "partial-dest", false);
    check(!partial && !fs::exists(temp.dir / "partial-dest"),
          "Failed partial Restic extraction leaves no published destination");
    unsetenv("SV_MOCK_FAIL_RESTORE");

    setenv("SV_MOCK_EXTRA_SQL", "1", 1);
    auto unexpected_sql = restic_restore(std::string(64, 'b'), "postgresql",
                                         temp.dir / "unexpected-sql", true);
    check(!unexpected_sql && !fs::exists(temp.dir / "unexpected-sql"),
          "Unexpected files block private SQL export");
    unsetenv("SV_MOCK_EXTRA_SQL");

    const auto racing_target = temp.dir / "racing-dest";
    setenv("SV_MOCK_RACE_DEST", racing_target.c_str(), 1);
    auto race = restic_restore(std::string(64, 'a'), "files", racing_target, false);
    check(!race && fs::exists(racing_target / "sentinel"),
          "Exclusive publish refuses a newly created destination");
    unsetenv("SV_MOCK_RACE_DEST");

    std::size_t remaining_stages = 0;
    for (const auto& item : fs::directory_iterator(temp.dir))
        if (item.path().filename().string().starts_with(".securevault-stage-"))
            ++remaining_stages;
    check(remaining_stages == 0, "All failed restore staging directories cleaned");

    auto bad_stanza = pitr_plan_pg("../production", "2024-01-01T00:00:00Z", "/var/lib/postgresql");
    check(!bad_stanza, "PITR rejects unsafe stanza");
    auto bad_clock = pitr_plan_mariadb("2024-01-01T12:00:00", "/srv/securevault-recovery/test");
    check(!bad_clock, "PITR rejects time without timezone");
    auto audit = pitr_audit();
    check(audit && (*audit)["read_only"].asBool() &&
          !(*audit)["changes_applied"].asBool(), "PITR audit is read-only");

    const auto logs = temp.dir / "logs";
    const auto state = temp.dir / "state";
    fs::create_directory(logs);
    fs::create_directory(state);
    file(logs / "mysql-bin.000001", "ABCD");
    file(logs / "mysql-bin.000002", "OPEN");
    const auto defaults = temp.dir / "database.cnf";
    file(defaults, "[client]\nuser=example\n");
    chmod(defaults.c_str(), 0600);
    Json::Value config;
    config["instance_id"] = "sample";
    config["binlog_prefix"] = "mysql-bin";
    config["binlog_dir"] = logs.string();
    config["state_file"] = (state / "checkpoint.json").string();
    config["db_defaults_file"] = defaults.string();
    const auto config_path = temp.dir / "shipper.json";
    Json::StreamWriterBuilder builder;
    file(config_path, Json::writeString(builder, config));
    chmod(config_path.c_str(), 0600);
    auto dry = binlog_ship(config_path, false);
    check(dry && (*dry)["pending_closed_logs"].size() == 1 &&
          (*dry)["active_excluded"].asString() == "mysql-bin.000002",
          "Dry run excludes active MariaDB binlog");
    check(!fs::exists(state / "checkpoint.json"), "Dry run never advances checkpoint");
    auto shipped = binlog_ship(config_path, true);
    check(shipped && (*shipped)["uploaded"].size() == 1, "Closed binlog shipped");
    auto checkpoint = parse_json([&]() {
        std::ifstream in(state / "checkpoint.json");
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }());
    check(checkpoint && (*checkpoint)["last_sequence"].asUInt64() == 1,
          "Checkpoint advanced only after acknowledged upload");
    auto second = binlog_ship(config_path, false);
    check(second && (*second)["pending_closed_logs"].empty(), "Idempotent repeated shipment");
    // Server rotation makes the previously active segment closed.
    setenv("SV_MOCK_MORE_BINLOGS", "1", 1);
    setenv("SV_MOCK_UPLOAD_FAIL", "1", 1);
    auto failed = binlog_ship(config_path, true);
    check(!failed, "Failed Restic shipment is reported");
    auto checkpoint_after_failure = parse_json([&]() {
        std::ifstream in(state / "checkpoint.json");
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }());
    check(checkpoint_after_failure && (*checkpoint_after_failure)["last_sequence"].asUInt64() == 1,
          "Upload failure never advances binlog checkpoint");
    unsetenv("SV_MOCK_UPLOAD_FAIL");
    unsetenv("SV_MOCK_MORE_BINLOGS");

    setenv("SV_MOCK_GAP_BINLOGS", "1", 1);
    auto gap = binlog_ship(config_path, false);
    check(!gap, "Gap in server binlog listing rejects backup");
    unsetenv("SV_MOCK_GAP_BINLOGS");

    // A corrupted/dangling checkpoint path must never be treated as new.
    const auto dangling = state / "dangling-checkpoint.json";
    fs::create_symlink(state / "missing-checkpoint", dangling);
    config["state_file"] = dangling.string();
    file(config_path, Json::writeString(builder, config));
    auto bad_checkpoint = binlog_ship(config_path, false);
    check(!bad_checkpoint, "Dangling checkpoint symlink fails closed");
    config["state_file"] = (state / "checkpoint.json").string();
    file(config_path, Json::writeString(builder, config));

    setenv("SV_MOCK_MORE_BINLOGS", "1", 1);
    setenv("SV_MOCK_BINLOG_MUTATE", "1", 1);
    auto mutated = binlog_ship(config_path, true);
    check(!mutated, "Closed binlog content mutation during upload fails");
    auto after_mutation = parse_json([&]() {
        std::ifstream in(state / "checkpoint.json");
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }());
    check(after_mutation && (*after_mutation)["last_sequence"].asUInt64() == 1,
          "Content mutation cannot advance the last good checkpoint");
    unsetenv("SV_MOCK_BINLOG_MUTATE");
    unsetenv("SV_MOCK_MORE_BINLOGS");
    std::cout << "SecureVault C++23 native tests: " << (checks - failures)
              << "/" << checks << " passed\n";
    return failures ? 1 : 0;
}
