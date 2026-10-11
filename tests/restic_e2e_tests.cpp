#include "operations.hpp"
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;
using securevault::ops::execute;
using securevault::ops::parse_json;

namespace {
struct Temp {
    fs::path root;
    Temp() {
        auto pattern = (fs::temp_directory_path() / "securevault-real-restic-XXXXXX").string();
        std::vector<char> path(pattern.begin(), pattern.end());
        path.push_back('\0');
        if (!mkdtemp(path.data())) throw std::runtime_error("Cannot create temporary integration directory");
        root = path.data();
    }
    ~Temp() { std::error_code ec; fs::remove_all(root, ec); }
};
void require(bool ok, std::string_view reason) {
    if (!ok) throw std::runtime_error(std::string(reason));
}
void write(const fs::path& path, const std::string& content) {
    std::ofstream out(path, std::ios::binary);
    out << content;
    require(static_cast<bool>(out), "Cannot write fixture file");
}
std::string read(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
void must_succeed(std::initializer_list<std::string> args, std::chrono::seconds timeout) {
    const auto result = execute(std::vector<std::string>(args), false, timeout);
    require(result.has_value() && result->exit_code == 0, "Real restic CLI command failed");
}
} // namespace

int main() {
    // This test is optional: CTest marks exit 77 as SKIPPED if restic is absent.
    if (!securevault::ops::has_tool("restic")) {
        std::cout << "SKIP: real Restic executable is not installed; no packages installed\n";
        return 77;
    }
    try {
        Temp test;
        const auto repository = test.root / "encrypted-repository";
        const auto source = test.root / "input";
        const auto password = test.root / "secret";
        const auto wrong_password = test.root / "wrong-password";
        fs::create_directories(source / "subdir");
        const std::string payload = "securevault-sensitive-test-only-payload-482a3d\n";
        write(source / "subdir" / "critical.txt", payload);
        fs::create_symlink("subdir/critical.txt", source / "relative-link");
        write(password, "local-fixture-password-very-secret-9384b1\n");
        write(wrong_password, "definitely-not-the-test-password\n");
        chmod(password.c_str(), 0600);
        chmod(wrong_password.c_str(), 0600);
        setenv("RESTIC_REPOSITORY", repository.c_str(), 1);
        setenv("RESTIC_PASSWORD_FILE", password.c_str(), 1);
        unsetenv("RESTIC_PASSWORD");
        unsetenv("RESTIC_PASSWORD_COMMAND");

        // RESTIC_REPOSITORY points ONLY to a fresh local fixture directory.
        // Production SecureVault deliberately rejects local repositories.
        require(!securevault::ops::remote_restic(),
                "Production off-site preflight unexpectedly accepted a local test repository");
        must_succeed({"restic", "init"}, std::chrono::seconds{120});
        must_succeed({"restic", "backup", "--tag", "securevault", "--tag", "files",
                      source.string()}, std::chrono::minutes{5});

        const auto inventory = execute({"restic", "snapshots", "--json"}, true,
                                        std::chrono::seconds{120});
        require(inventory && inventory->exit_code == 0, "Cannot read real Restic snapshots");
        const auto snapshots = parse_json(inventory->out);
        require(snapshots && snapshots->isArray() && snapshots->size() == 1,
                "Real Restic must publish one snapshot");
        const std::string id = (*snapshots)[0]["id"].asString();
        require(id.size() == 64, "Real Restic did not return a full snapshot ID");

        must_succeed({"restic", "check", "--read-data"}, std::chrono::minutes{10});
        const auto target = test.root / "restored";
        must_succeed({"restic", "restore", id, "--target", target.string()},
                     std::chrono::minutes{5});
        const auto output = target / source.relative_path();
        require(read(output / "subdir" / "critical.txt") == payload,
                "Restored file bytes do not match source");
        require(fs::is_symlink(output / "relative-link") &&
                fs::read_symlink(output / "relative-link") == "subdir/critical.txt",
                "Real Restic did not preserve the relative symlink");

        // An incorrect key must never allow repository metadata to be opened.
        setenv("RESTIC_PASSWORD_FILE", wrong_password.c_str(), 1);
        const auto rejected = execute({"restic", "snapshots", "--json"}, true,
                                      std::chrono::seconds{120});
        require(rejected && rejected->exit_code != 0, "Restic accepted an incorrect encryption password");
        setenv("RESTIC_PASSWORD_FILE", password.c_str(), 1);

        // Ensure the known sensitive marker was not written as plaintext in
        // the small, dedicated repository. This is a smoke check, not a
        // cryptographic proof of the encryption algorithm.
        for (const auto& item : fs::recursive_directory_iterator(repository)) {
            if (!item.is_regular_file()) continue;
            const auto raw = read(item.path());
            require(raw.find(payload) == std::string::npos,
                    "Sensitive test data unexpectedly found as plaintext in the repository");
        }

        std::cout << "REAL Restic: encrypted backup, snapshot inventory, data check, "
                     "restore, symlink, wrong password and plaintext smoke checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "REAL Restic integration test FAILED: " << error.what() << '\n';
        return 1;
    }
}
