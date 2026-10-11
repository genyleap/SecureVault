#include "operations.hpp"
#include <iostream>
#include <map>

namespace securevault::ops {
int entry(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: securevault-ops <restic|pitr|binlog> <action> [options]\n";
        return 2;
    }
    std::string group = argv[1];
    std::string action = argc > 2 ? argv[2] : "";
    std::map<std::string, std::string> values;
    bool plaintext = false, ship = false;
    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--allow-plaintext-export") plaintext = true;
        else if (arg == "--execute") ship = true;
        else if (arg.starts_with("--") && i + 1 < argc) values[arg] = argv[++i];
        else { std::cerr << "Unrecognized/partial CLI option\n"; return 2; }
    }
    auto required = [&](std::string_view option) -> std::string {
        const auto it = values.find(std::string(option));
        return it == values.end() ? "" : it->second;
    };
    Result result = std::unexpected("Unrecognized operation");
    if (group == "restic") {
        if (action == "list") result = restic_list();
        else if (action == "generations") result = restic_generations();
        else if (action == "check") result = restic_check();
        else if (action == "backup") result = restic_backup();
        else if (action == "restore") {
            if (required("--snapshot").empty() || required("--kind").empty() || required("--target").empty())
                result = std::unexpected("Restore requires --snapshot, --kind and --target");
            else result = restic_restore(required("--snapshot"), required("--kind"), required("--target"), plaintext);
        }
    } else if (group == "pitr") {
        if (action == "audit") result = pitr_audit();
        else if (action == "plan-postgresql") {
            if (required("--stanza").empty() || required("--target-time").empty() || required("--dest").empty())
                result = std::unexpected("Missing required PITR plan arguments");
            else result = pitr_plan_pg(required("--stanza"), required("--target-time"), required("--dest"));
        } else if (action == "plan-mariadb") {
            if (required("--target-time").empty() || required("--dest").empty())
                result = std::unexpected("Missing required MariaDB plan arguments");
            else result = pitr_plan_mariadb(required("--target-time"), required("--dest"));
        }
    } else if (group == "binlog" && action == "ship") {
        if (required("--config").empty()) result = std::unexpected("Binlog requires --config");
        else result = binlog_ship(required("--config"), ship);
    }
    if (!result) {
        // Error messages never echo potentially sensitive child stderr or CLI credentials.
        std::cerr << "SecureVault operation failed: " << result.error() << '\n';
        return 1;
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    std::cout << Json::writeString(builder, *result);
    if (group == "pitr" && action == "audit" &&
        (!(*result)["postgresql"]["local_prerequisites_met"].asBool() ||
         !(*result)["mariadb"]["local_prerequisites_met"].asBool()))
        return 2; // An audit report is not proof of local readiness.
    return 0;
}
} // namespace securevault::ops

int main(int argc, char** argv) {
    return securevault::ops::entry(argc, argv);
}
