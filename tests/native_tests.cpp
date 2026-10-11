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
        const std::string a(64, 'a'), b(64, 'b'), c(64, 'c');
        if (action == "snapshots") {
            std::cout << "["
                "{\"id\":\"" << a << "\",\"tags\":[\"securevault\",\"files\",\"20261011T090000Z\"]},"
                "{\"id\":\"" << b << "\",\"tags\":[\"securevault\",\"postgresql\",\"20261011T090000Z\"]}"
                << (std::getenv("SV_MOCK_MISSING_MARIA") ? "" :
                    ",{\"id\":\"" + c + "\",\"tags\":[\"securevault\",\"mariadb\",\"20261011T090000Z\"]}")
                << "]\n";
        } else if (action == "restore") {
            std::string target;
            for (int i = 2; i + 1 < argc; ++i)
                if (std::string_view(argv[i]) == "--target") target = argv[i + 1];
            if (target.empty()) return 42;
            if (argv[2] == b) file(fs::path(target) / "postgresql-all.sql", "SELECT 1;\n");
            else {
                fs::create_directories(fs::path(target) / "var" / "www");
                file(fs::path(target) / "var" / "www" / "index.txt", "restored contents\n");
                if (std::getenv("SV_MOCK_EVIL_SYMLINK"))
                    fs::create_symlink("/etc/passwd", fs::path(target) / "evil");
            }
        } else if (action == "backup") {
            if (std::getenv("SV_MOCK_UPLOAD_FAIL")) return 23;
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
                if (std::getenv("SV_MOCK_MORE_BINLOGS"))
                    std::cout << "mysql-bin.000001\t4\nmysql-bin.000002\t4\nmysql-bin.000003\t4\n";
                else
                    std::cout << "mysql-bin.000001\t4\nmysql-bin.000002\t4\n";
                return 0;
            }
            if (argument == "SHOW MASTER STATUS") {
                std::cout << (std::getenv("SV_MOCK_MORE_BINLOGS") ?
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
    check(inventory && inventory->size() == 3, "Restic lists only trusted snapshots");
    auto groups = restic_generations();
    check(groups && groups->size() == 1 &&
          (*groups)[0]["status"].asString() == "COMPLETE", "Three-part generation completeness");
    setenv("SV_MOCK_MISSING_MARIA", "1", 1);
    auto incomplete = restic_generations();
    check(incomplete && (*incomplete)[0]["status"].asString() == "INCOMPLETE",
          "A missing database snapshot makes the generation incomplete");
    unsetenv("SV_MOCK_MISSING_MARIA");
    auto integrity = restic_check();
    check(integrity && (*integrity)["checked"].asBool(), "Restic integrity check");
    setenv("SV_MOCK_CHECK_FAIL", "1", 1);
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
    std::cout << "SecureVault C++23 native tests: " << (checks - failures)
              << "/" << checks << " passed\n";
    return failures ? 1 : 0;
}
