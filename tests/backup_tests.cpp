#include "operations.hpp"
#include <archive.h>
#include <archive_entry.h>
#include <json/json.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>

namespace fs = std::filesystem;
namespace {
int checks = 0, errors = 0;
void check(bool value, std::string_view label) {
    ++checks;
    if (!value) { ++errors; std::cerr << "FAIL: " << label << '\n'; }
}
struct Temp {
    fs::path path;
    Temp() {
        const auto sample = (fs::temp_directory_path() / "securevault-backup-cpp-XXXXXX").string();
        std::vector<char> chars(sample.begin(), sample.end());
        chars.push_back(0);
        if (!mkdtemp(chars.data())) throw std::runtime_error("Cannot make private test directory");
        path = chars.data();
    }
    ~Temp() { std::error_code ignore; fs::remove_all(path, ignore); }
};
void write(const fs::path& file, const std::string& text) {
    std::ofstream out(file, std::ios::binary);
    out << text;
}
std::expected<fs::path, std::string> archive_at(const fs::path& backup_base) {
    const auto sys = backup_base / "sys";
    if (!fs::is_directory(sys)) return std::unexpected("Archive directory missing");
    for (const auto& item : fs::directory_iterator(sys))
        if (item.path().extension() == ".gz") return item.path();
    return std::unexpected("Archive not created");
}
void malicious(const fs::path& archive_path, const std::string& name) {
    auto* writer = archive_write_new();
    archive_write_add_filter_gzip(writer);
    archive_write_set_format_pax_restricted(writer);
    if (archive_write_open_filename(writer, archive_path.c_str()) != ARCHIVE_OK)
        throw std::runtime_error("Cannot create archive");
    auto* entry = archive_entry_new();
    archive_entry_set_pathname(entry, name.c_str());
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_entry_set_size(entry, 4);
    archive_write_header(writer, entry);
    archive_write_data(writer, "evil", 4);
    archive_entry_free(entry);
    archive_write_close(writer);
    archive_write_free(writer);
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string bin = fs::absolute(argv[1]).string();
    Temp tmp;
    auto source = tmp.path / "source";
    auto backup = tmp.path / "backups";
    fs::create_directories(source / "empty");
    write(source / "critical.txt", "critical backup data\n");
    fs::permissions(source / "critical.txt", fs::perms::owner_read |
        fs::perms::owner_write | fs::perms::group_read);
    fs::create_symlink("critical.txt", source / "link");
    Json::Value cfg;
    cfg["backup_base"] = backup.string() + "/";
    cfg["backup_dirs"].append(source.string());
    cfg["databases"] = Json::arrayValue;
    cfg["exclude_extensions"] = Json::arrayValue;
    cfg["retention_days"] = 30;
    cfg["schedule"]["type"] = "daily";
    cfg["schedule"]["time"] = "03:00:00";
    auto config = tmp.path / "config.json";
    Json::StreamWriterBuilder builder;
    write(config, Json::writeString(builder, cfg));
    auto result = securevault::ops::execute({bin, "--config", config.string(), "daily"}, false);
    check(result && result->exit_code == 0, "File-only backup succeeds");
    auto output = archive_at(backup);
    check(output.has_value(), "Full archive exists");
    if (output) {
        auto verified = securevault::ops::execute({bin, "verify", output->string()}, false);
        check(verified && verified->exit_code == 0, "Tar archive payload verification succeeds");
        auto destination = tmp.path / "recovered";
        auto restored = securevault::ops::execute(
            {bin, "restore", output->string(), destination.string()}, false);
        check(restored && restored->exit_code == 0, "Safe staged extraction succeeds");
        auto relative = source.relative_path();
        std::ifstream recovered(destination / relative / "critical.txt");
        std::string content;
        std::getline(recovered, content);
        check(content == "critical backup data", "Restored file data matches");
        check(fs::is_symlink(destination / relative / "link"), "Restore preserves symlink");
        check(fs::is_directory(destination / relative / "empty"), "Empty directory is restored");
        auto refusal = securevault::ops::execute(
            {bin, "restore", output->string(), destination.string()}, false);
        check(refusal && refusal->exit_code != 0, "Restore refuses overwrite");
    }
    auto invalid = tmp.path / "attack.tar.gz";
    malicious(invalid, "../escape");
    auto reject = securevault::ops::execute({bin, "verify", invalid.string()}, false);
    check(reject && reject->exit_code != 0, "Archive path traversal refused");
    auto unsafe = securevault::ops::execute(
        {bin, "--config", config.string(), "--incremental", "daily"}, false);
    check(unsafe && unsafe->exit_code != 0, "Unsafe incremental mode is disabled");

    cfg["require_remote"] = true;
    write(config, Json::writeString(builder, cfg));
    auto fail_remote = securevault::ops::execute({bin, "--config", config.string(), "daily"}, false);
    check(fail_remote && fail_remote->exit_code != 0, "Off-site required without configuration fails");
    cfg["require_remote"] = false;
    cfg["backup_dirs"] = Json::arrayValue;
    cfg["backup_dirs"].append((tmp.path / "missing-source").string());
    write(config, Json::writeString(builder, cfg));
    auto fail_missing = securevault::ops::execute({bin, "--config", config.string(), "daily"}, false);
    check(fail_missing && fail_missing->exit_code != 0, "Missing required files fail backup");

    std::cout << "SecureVault C++ backup tests: " << checks - errors << '/' << checks << " passed\n";
    return errors ? 1 : 0;
}
