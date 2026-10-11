#include "vault.hpp"
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace securevault::vault;
namespace {
int cases = 0, failures = 0;
void check(bool ok, const std::string& name) {
    ++cases;
    if (!ok) { ++failures; std::cerr << "FAIL: " << name << '\n'; }
}
struct Tmp {
    fs::path path;
    Tmp() {
        auto s = (fs::temp_directory_path() / "svlt-native-cpp-XXXXXX").string();
        std::vector<char> data(s.begin(), s.end());
        data.push_back('\0');
        if (!mkdtemp(data.data())) throw std::runtime_error("Cannot make test dir");
        path = data.data();
    }
    ~Tmp() { std::error_code ec; fs::remove_all(path, ec); }
};
void write(const fs::path& p, std::string_view s) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(s.data(), static_cast<std::streamsize>(s.size()));
}
std::string read(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}
} // namespace
int main(int argc, char** argv) {
    (void)argc;
    const auto invoked = fs::path(argv[0]).filename().string();
    if (invoked == "pg_dumpall" || invoked == "mariadb-dump") {
        std::cout << (invoked == "pg_dumpall"
            ? "CREATE ROLE synthetic_role;\\n"
            : "CREATE DATABASE synthetic_mariadb;\\n");
        if (std::getenv("SV_TEST_DB_FAIL")) return 21;
        return 0;
    }
    Tmp tmp;
    const auto repo = tmp.path / "vault";
    const auto pass = tmp.path / "secret";
    const auto wrong = tmp.path / "wrong";
    const auto source = tmp.path / "data";
    fs::create_directories(source / "nested");
    fs::create_directories(source / "empty");
    write(pass, "generated-test-only-password-123456789\n");
    write(wrong, "incorrect-password-xxxxxxxxxxxxx\n");
    chmod(pass.c_str(), 0600);
    chmod(wrong.c_str(), 0600);
    const std::string secret = "PASSWORDS-ONLY-IN-THE-TEST-PLAINTEXT\n";
    write(source / "nested" / "file.txt", secret);
    std::string large(1024 * 1024, '\0');
    for (std::size_t i = 0; i < large.size(); ++i)
        large[i] = static_cast<char>((i * 13 + 77) % 251);
    write(source / "nested" / "large.bin", large);
    fs::create_symlink("nested/file.txt", source / "link");

    check(initialize(repo).has_value(), "Can initialize a private native repository");
    check(!initialize(repo), "Cannot overwrite an existing repository");
    auto archive = create(repo, source, pass);
    check(archive && fs::is_regular_file(*archive), "Creates an encrypted native archive");
    if (!archive) {
        std::cerr << "Native create error: " << archive.error() << '\n';
        return 1;
    }
    const auto digest = ciphertext_digest(*archive);
    check(digest && archive->filename().string() == *digest + ".svlt",
          "New archive IDs are SHA-256 of authenticated ciphertext");
    check(verify(*archive, pass).has_value(), "Authenticates the complete snapshot");
    check(!verify(*archive, wrong), "Rejects a wrong password");
    auto inventory = list(repo);
    check(inventory && inventory->size() == 1 && inventory->front() == *archive,
          "Lists only committed snapshots");
    check(!create(repo, tmp.path, pass),
          "Refuses recursive self-backup when repository lives inside the source");
    check(!create(repo, *archive, pass),
          "Refuses to recursively back up vault snapshot files");
    const auto source_key = source / "accidental-password";
    write(source_key, "sensitive-password-file-in-source");
    chmod(source_key.c_str(), 0600);
    check(!create(repo, source, source_key),
          "Refuses snapshots containing their own encryption key file");
    fs::remove(source_key);
    const auto blob = read(*archive);
    check(blob.find(secret) == std::string::npos, "Encrypted snapshot hides plaintext marker");
    check(blob.find(large.substr(1024, 1024)) == std::string::npos,
          "Encrypted binary file is not stored in plaintext");

    auto restore_dir = tmp.path / "recovery";
    const auto recovered = restore(*archive, restore_dir, pass);
    if (!recovered) std::cerr << "Native restore error: " << recovered.error() << '\n';
    check(recovered.has_value(), "Authenticated restore succeeds");
    check(read(restore_dir / "nested" / "file.txt") == secret,
          "Restored file contents are exact");
    check(read(restore_dir / "nested" / "large.bin") == large,
          "Streaming restores a one-megabyte binary file");
    check(fs::is_directory(restore_dir / "empty"), "Preserves empty directory");
    const auto nested_mode = fs::status(restore_dir / "nested").permissions();
    check((static_cast<unsigned>(nested_mode) & 077) == 0,
          "Restored nested directories have private 0700 permissions");
    check(fs::is_symlink(restore_dir / "link") &&
          fs::read_symlink(restore_dir / "link") == "nested/file.txt",
          "Preserves safe relative symlink");
    check(!restore(*archive, restore_dir, pass), "Refuses to overwrite destination");
    fs::create_symlink(tmp.path, tmp.path / "linked-parent");
    check(!restore(*archive, tmp.path / "linked-parent" / "escaped", pass) &&
          !fs::exists(tmp.path / "escaped"),
          "Restore rejects a symlinked destination parent");
    check(!restore(*archive, tmp.path / "wrong-key-target", wrong) &&
          !fs::exists(tmp.path / "wrong-key-target"),
          "Wrong key does not publish a destination");

    auto corrupt = tmp.path / "corrupt.svlt";
    auto modified = blob;
    if (modified.size() > 100) modified[100] ^= 1;
    write(corrupt, modified);
    check(!verify(corrupt, pass), "AES-GCM detects ciphertext modification");
    check(!restore(corrupt, tmp.path / "tampered", pass) &&
          !fs::exists(tmp.path / "tampered"),
          "Tampered archive is never published");
    write(corrupt, blob.substr(0, blob.size() - 7));
    check(!verify(corrupt, pass), "Rejects truncated encrypted archive");
    modified = blob;
    modified[0] ^= 7;
    write(corrupt, modified);
    check(!verify(corrupt, pass), "Rejects unknown format header");

    auto bad_pass = tmp.path / "world-readable";
    write(bad_pass, "test-secret-with-insecure-permissions\n");
    chmod(bad_pass.c_str(), 0644);
    check(!create(repo, source, bad_pass), "Rejects world-readable key file");
    fs::create_symlink(pass, tmp.path / "linked-secret");
    check(!create(repo, source, tmp.path / "linked-secret"),
          "Rejects symbolic-link key file");
    fs::create_symlink("/etc/passwd", source / "escape");
    check(!create(repo, source, pass), "Rejects absolute symlink to outside tree");
    fs::remove(source / "escape");
    fs::create_hard_link(source / "nested" / "file.txt", source / "hardlink");
    check(!create(repo, source, pass), "Refuses hardlinked source files");
    fs::remove(source / "hardlink");

    const auto single = create(repo, source / "nested" / "file.txt", pass);
    check(single.has_value(), "Can encrypt individual files");
    auto single_target = tmp.path / "single-output";
    check(single && restore(*single, single_target, pass) &&
          read(single_target / "file.txt") == secret,
          "Can restore an individual file in a private target directory");
    auto second = list(repo);
    check(second && second->size() == 2, "Two independent native snapshots visible");

    const auto bad_url = tmp.path / "url-file";
    write(bad_url, "http://127.0.0.1/forbidden\n");
    chmod(bad_url.c_str(), 0600);
    check(!upload_https(*archive, pass, bad_url),
          "Rejects plaintext HTTP upload endpoint");
    check(!download_https(repo, std::string(32, 'c'), pass, bad_url),
          "Rejects plaintext HTTP download endpoint");
    write(bad_url, "https://127.0.0.1:1/offsite/snapshot.svlt\n");
    chmod(bad_url.c_str(), 0644);
    check(!upload_https(*archive, pass, bad_url),
          "Rejects insecure URL credentials file permissions");
    chmod(bad_url.c_str(), 0600);
    fs::create_symlink(bad_url, tmp.path / "url-symlink");
    check(!upload_https(*archive, pass, tmp.path / "url-symlink"),
          "Rejects URL file symlinks");
    check(!download_https(repo, "../outside", pass, bad_url),
          "Rejects unsafe downloaded snapshot IDs");
    check(!upload_https(corrupt, pass, bad_url),
          "Rejects unauthenticated encrypted upload source");
    check(!download_https(repo, std::string(64, 'd'), pass, bad_url) &&
          !fs::exists(repo / (std::string(64, 'd') + ".svlt")),
          "HTTPS failure leaves no published encrypted snapshot");

    // Simulate both database programs with THIS C++23 test executable;
    // stdout flows directly into AES-GCM without touching an SQL temp file.
    const auto mockbin = tmp.path / "mock-db-bin";
    fs::create_directory(mockbin);
    const auto self = fs::canonical(argv[0]);
    fs::create_symlink(self, mockbin / "pg_dumpall");
    fs::create_symlink(self, mockbin / "mariadb-dump");
    const std::string old_path = std::getenv("PATH") ? std::getenv("PATH") : "";
    const std::string mock_path = mockbin.string() + ":" + old_path;
    setenv("PATH", mock_path.c_str(), 1);
    auto pg = create_logical_dump(repo, pass, "postgresql");
    check(pg && verify(*pg, pass), "PostgreSQL logical stdout encrypted directly");
    const auto pg_dest = tmp.path / "pg-restored";
    check(pg && restore(*pg, pg_dest, pass) &&
          read(pg_dest / "postgresql-all.sql").find("synthetic_role") != std::string::npos,
          "PostgreSQL logical export restores from authenticated ciphertext");
    auto maria = create_logical_dump(repo, pass, "mariadb");
    check(maria && verify(*maria, pass), "MariaDB logical stdout encrypted directly");
    const auto maria_dest = tmp.path / "maria-restored";
    check(maria && restore(*maria, maria_dest, pass) &&
          read(maria_dest / "mariadb-all.sql").find("synthetic_mariadb") != std::string::npos,
          "MariaDB logical export restores from authenticated ciphertext");
    check(!create_logical_dump(repo, pass, "unsupported"),
          "Unexpected database engines are refused");
    const auto before_failure = list(repo);
    setenv("SV_TEST_DB_FAIL", "1", 1);
    check(!create_logical_dump(repo, pass, "postgresql"),
          "Failed SQL producer cannot publish an encrypted snapshot");
    unsetenv("SV_TEST_DB_FAIL");
    const auto after_failure = list(repo);
    check(before_failure && after_failure &&
          before_failure->size() == after_failure->size(),
          "Failed database producer leaves snapshot inventory unchanged");
    setenv("PATH", old_path.c_str(), 1);
    std::cout << "SecureVault C++23 vault: " << cases - failures
              << "/" << cases << " checks passed\n";
    return failures ? 1 : 0;
}
