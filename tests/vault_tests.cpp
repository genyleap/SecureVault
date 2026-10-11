#include "vault.hpp"
#include <array>
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
int main() {
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
    check(verify(*archive, pass).has_value(), "Authenticates the complete snapshot");
    check(!verify(*archive, wrong), "Rejects a wrong password");
    auto inventory = list(repo);
    check(inventory && inventory->size() == 1 && inventory->front() == *archive,
          "Lists only committed snapshots");
    check(!create(repo, tmp.path, pass),
          "Refuses recursive self-backup when repository lives inside the source");
    check(!create(repo, *archive, pass),
          "Refuses to recursively back up vault snapshot files");
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
    check(fs::is_symlink(restore_dir / "link") &&
          fs::read_symlink(restore_dir / "link") == "nested/file.txt",
          "Preserves safe relative symlink");
    check(!restore(*archive, restore_dir, pass), "Refuses to overwrite destination");
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
    std::cout << "SecureVault C++23 vault: " << cases - failures
              << "/" << cases << " checks passed\n";
    return failures ? 1 : 0;
}
