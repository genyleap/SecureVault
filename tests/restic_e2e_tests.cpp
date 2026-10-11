#include "operations.hpp"
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using securevault::ops::execute;
using securevault::ops::parse_json;
using securevault::ops::inspect_restic_generations;

namespace {
struct Temp {
    fs::path root;
    Temp() {
        auto pattern = (fs::temp_directory_path() / "securevault-real-restic-XXXXXX").string();
        std::vector<char> chars(pattern.begin(), pattern.end());
        chars.push_back('\0');
        if (!mkdtemp(chars.data()))
            throw std::runtime_error("Cannot create private Restic test directory");
        root = chars.data();
    }
    ~Temp() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
};
void require(bool ok, std::string_view message) {
    if (!ok) throw std::runtime_error(std::string(message));
}
void write(const fs::path& file, const std::string& contents) {
    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    out << contents;
    require(static_cast<bool>(out), "Cannot write a temporary test fixture");
}
std::string read(const fs::path& file) {
    std::ifstream in(file, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
void succeed(std::initializer_list<std::string> argv, std::chrono::seconds deadline) {
    const auto result = execute(std::vector<std::string>(argv), false, deadline);
    require(result && result->exit_code == 0, "Real Restic CLI command failed");
}
Json::Value inventory() {
    const auto result = execute({"restic", "snapshots", "--json", "--tag", "securevault"},
                                true, std::chrono::seconds{120});
    require(result && result->exit_code == 0, "Cannot read actual Restic snapshots");
    auto json = parse_json(result->out);
    require(json && json->isArray(), "Invalid Restic snapshots JSON");
    return *json;
}
bool has_tag(const Json::Value& snapshot, const std::string& tag) {
    for (const auto& item : snapshot["tags"])
        if (item.isString() && item.asString() == tag) return true;
    return false;
}
std::string unique_snapshot_id(const Json::Value& snapshots,
                               const std::string& tag,
                               const std::string& generation) {
    std::string id;
    for (const auto& snapshot : snapshots) {
        if (!has_tag(snapshot, tag) || !has_tag(snapshot, generation)) continue;
        require(id.empty(), "Multiple snapshots unexpectedly share one kind");
        id = snapshot.get("id", "").asString();
    }
    require(id.size() == 64, "Restic did not return one full SHA snapshot ID");
    return id;
}
} // namespace

int main() {
    // No installation and no contact with operator-owned repositories.
    // Missing Restic is SKIPPED, never mistaken for a successful real drill.
    if (!securevault::ops::has_tool("restic")) {
        std::cout << "SKIP: real Restic executable is not installed\n";
        return 77;
    }
    try {
        Temp test;
        const auto repository = test.root / "encrypted-repository";
        const auto source = test.root / "input";
        const auto markers = test.root / "markers";
        const auto password = test.root / "secret";
        const auto wrong_password = test.root / "wrong-password";
        const auto pg = test.root / "postgresql-all.sql";
        const auto maria = test.root / "mariadb-all.sql";
        const std::string stamp = "20261011T090000Z";
        const std::string payload = "securevault-sensitive-test-only-payload-482a3d\n";

        fs::create_directories(source / "subdir");
        fs::create_directory(markers);
        write(source / "subdir" / "critical.txt", payload);
        fs::create_symlink("subdir/critical.txt", source / "relative-link");
        write(pg, "SELECT 'synthetic postgres fixture';\n");
        write(maria, "SELECT 'synthetic mariadb fixture';\n");
        write(password, "temporary-repository-secret-password-9384b1\n");
        write(wrong_password, "definitely-not-the-test-password\n");
        chmod(password.c_str(), 0600);
        chmod(wrong_password.c_str(), 0600);

        setenv("RESTIC_REPOSITORY", repository.c_str(), 1);
        setenv("RESTIC_PASSWORD_FILE", password.c_str(), 1);
        unsetenv("RESTIC_PASSWORD");
        unsetenv("RESTIC_PASSWORD_COMMAND");

        // The production API must refuse the temporary LOCAL repository.
        require(!securevault::ops::remote_restic(),
                "Production remote-only requirement was bypassed by the test");

        succeed({"restic", "init"}, std::chrono::seconds{120});
        succeed({"restic", "backup", "--tag", "securevault", "--tag", "files",
                 "--tag", stamp, source.string()}, std::chrono::minutes{5});
        succeed({"restic", "backup", "--tag", "securevault", "--tag", "postgresql",
                 "--tag", stamp, pg.string()}, std::chrono::minutes{5});
        succeed({"restic", "backup", "--tag", "securevault", "--tag", "mariadb",
                 "--tag", stamp, maria.string()}, std::chrono::minutes{5});

        auto first = inventory();
        require(first.size() == 3, "Expected three real Restic data snapshots");
        const auto before = inspect_restic_generations(first, markers);
        require(before && before->size() == 1 &&
                (*before)[0]["status"].asString() == "INCOMPLETE",
                "Three real data snapshots must not imply a committed generation");

        const std::string file_id = unique_snapshot_id(first, "files", stamp);
        Json::Value manifest;
        manifest["schema"] = "securevault.restic.generation.v2";
        manifest["generation"] = stamp;
        manifest["transactionally_consistent"] = false;
        manifest["snapshots"]["files"] = file_id;
        manifest["snapshots"]["postgresql"] =
            unique_snapshot_id(first, "postgresql", stamp);
        manifest["snapshots"]["mariadb"] =
            unique_snapshot_id(first, "mariadb", stamp);

        const auto marker = markers / ".generation-fixture";
        Json::StreamWriterBuilder writer;
        write(marker, Json::writeString(writer, manifest));
        chmod(marker.c_str(), 0600);
        succeed({"restic", "backup", "--tag", "securevault",
                 "--tag", "generation-committed", "--tag", stamp,
                 marker.string()}, std::chrono::minutes{5});

        auto committed = inventory();
        require(committed.size() == 4, "Expected three components and one encrypted marker");
        auto checked = inspect_restic_generations(committed, markers);
        require(checked && checked->size() == 1 &&
                (*checked)[0]["committed"].asBool() &&
                (*checked)[0]["status"].asString() == "COMPLETE" &&
                (*checked)[0]["snapshots"]["files"].asString() == file_id,
                "Actual restic dump did not verify all three manifest snapshot IDs");

        // A duplicate second marker fails closed, even if one remains valid.
        // The test never alters or deletes the first committed snapshot.
        const auto extra = markers / ".generation-duplicate";
        write(extra, Json::writeString(writer, manifest));
        succeed({"restic", "backup", "--tag", "securevault",
                 "--tag", "generation-committed", "--tag", stamp,
                 extra.string()}, std::chrono::minutes{5});
        auto repeated = inspect_restic_generations(inventory(), markers);
        require(repeated && (*repeated)[0]["status"].asString() == "INCOMPLETE",
                "Two encrypted commit markers must not count as complete");

        succeed({"restic", "check", "--read-data"}, std::chrono::minutes{10});
        const auto target = test.root / "restored";
        succeed({"restic", "restore", file_id, "--target", target.string()},
                std::chrono::minutes{5});
        const auto output = target / source.relative_path();
        require(read(output / "subdir" / "critical.txt") == payload,
                "Restic restored different file bytes");
        require(fs::is_symlink(output / "relative-link") &&
                fs::read_symlink(output / "relative-link") == "subdir/critical.txt",
                "Restic did not preserve the relative file symlink");

        setenv("RESTIC_PASSWORD_FILE", wrong_password.c_str(), 1);
        const auto rejected = execute({"restic", "snapshots", "--json"},
                                      true, std::chrono::seconds{120});
        require(rejected && rejected->exit_code != 0,
                "Restic accepted the wrong repository password");
        setenv("RESTIC_PASSWORD_FILE", password.c_str(), 1);

        for (const auto& item : fs::recursive_directory_iterator(repository)) {
            if (!item.is_regular_file()) continue;
            require(read(item.path()).find(payload) == std::string::npos,
                    "Synthetic secret unexpectedly found in repository plaintext");
        }
        std::cout << "REAL Restic: encrypted snapshots, v2 generation manifest, "
                     "restic dump, duplicate-marker rejection, full data check, "
                     "restore, symlinks and wrong password passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "REAL Restic test FAILED: " << error.what() << '\n';
        return 1;
    }
}
