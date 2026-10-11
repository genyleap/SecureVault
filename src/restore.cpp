#include "restore.hpp"

#include <archive.h>
#include <archive_entry.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
namespace {
constexpr std::uint64_t max_entries = 1'000'000;
constexpr std::uint64_t max_regular_bytes = 1ULL << 40; // 1 TiB safety limit
constexpr auto buffer_size = std::size_t{64 * 1024};

std::string archive_error(struct archive* a, const std::string& prefix) {
    const char* why = archive_error_string(a);
    return prefix + (why ? why : "unknown libarchive error");
}

// Reject absolute paths, drive letters, traversal components, and Windows
// separators (ambiguous when an archive is moved between operating systems).
std::expected<fs::path, std::string> clean_entry_path(const char* name) {
    if (!name || !*name) return std::unexpected("Archive entry has no name");
    std::string raw(name);
    if (raw.find('\\') != std::string::npos || raw.find(':') != std::string::npos)
        return std::unexpected("Unsafe separator or drive syntax: " + raw);
    fs::path value(raw);
    if (value.is_absolute() || value.has_root_name() || value.has_root_directory())
        return std::unexpected("Absolute archive path: " + raw);
    for (const auto& part : value) {
        if (part == "..") return std::unexpected("Parent traversal in archive: " + raw);
    }
    value = value.lexically_normal();
    if (value.empty() || value == ".")
        return std::unexpected("Invalid empty archive path: " + raw);
    return value;
}

std::expected<void, std::string> validate_link_target(
    const fs::path& location, const char* target) {
    if (!target || !*target) return std::unexpected("Empty symlink target");
    std::string raw(target);
    if (raw.find('\\') != std::string::npos || raw.find(':') != std::string::npos)
        return std::unexpected("Unsafe symlink separator: " + raw);
    fs::path link(raw);
    if (link.is_absolute() || link.has_root_name() || link.has_root_directory())
        return std::unexpected("Absolute symlink target is forbidden: " + raw);
    fs::path resolved = (location.parent_path() / link).lexically_normal();
    if (resolved.empty() || resolved == ".") return std::unexpected("Symlink targets archive root");
    for (const auto& part : resolved) {
        if (part == "..") return std::unexpected("Symlink escapes the extraction root: " + raw);
    }
    return {};
}

struct EntryInfo {
    fs::path relative;
    int mode = 0;
    int filetype = 0;
};

std::expected<EntryInfo, std::string> validate_entry(archive_entry* entry) {
    auto relative = clean_entry_path(archive_entry_pathname(entry));
    if (!relative) return std::unexpected(relative.error());
    if (archive_entry_hardlink(entry))
        return std::unexpected("Hardlinks not supported: " + relative->string());
    const int type = archive_entry_filetype(entry);
    if (type != AE_IFREG && type != AE_IFDIR && type != AE_IFLNK)
        return std::unexpected("Unsupported special file: " + relative->string());
    if ((archive_entry_perm(entry) & 07000) != 0)
        return std::unexpected("Privileged archive mode rejected: " + relative->string());
    if (type == AE_IFLNK) {
        auto valid = validate_link_target(*relative, archive_entry_symlink(entry));
        if (!valid) return std::unexpected(valid.error());
    }
    if (type == AE_IFREG && archive_entry_size(entry) < 0)
        return std::unexpected("Unknown regular file size: " + relative->string());
    return EntryInfo{*relative, static_cast<int>(archive_entry_perm(entry) & 0777), type};
}

std::expected<struct archive*, std::string> open_archive(const std::string& filename) {
    struct archive* a = archive_read_new();
    if (!a) return std::unexpected("Cannot allocate archive reader");
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);
    if (archive_read_open_filename(a, filename.c_str(), 64 * 1024) != ARCHIVE_OK) {
        auto message = archive_error(a, "Cannot open backup archive: ");
        archive_read_free(a);
        return std::unexpected(message);
    }
    return a;
}

std::expected<ArchiveReport, std::string> scan_archive(const std::string& archive_path) {
    auto opened = open_archive(archive_path);
    if (!opened) return std::unexpected(opened.error());
    struct archive* a = *opened;
    archive_entry* entry = nullptr;
    std::set<fs::path> seen;
    std::set<fs::path> links;
    ArchiveReport report;
    std::array<char, buffer_size> buffer{};
    int code = ARCHIVE_OK;
    std::string error;
    while ((code = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        auto info = validate_entry(entry);
        if (!info) { error = info.error(); break; }
        if (!seen.insert(info->relative).second) {
            error = "Duplicate archive entry: " + info->relative.string(); break;
        }
        if (++report.entries > max_entries) { error = "Too many archive entries"; break; }
        if (info->filetype == AE_IFLNK) links.insert(info->relative);
        if (info->filetype == AE_IFREG) {
            const auto size = static_cast<std::uint64_t>(archive_entry_size(entry));
            if (size > max_regular_bytes - report.regular_bytes) {
                error = "Archive exceeds permitted uncompressed size"; break;
            }
            report.regular_bytes += size;
        }
        if (info->filetype != AE_IFREG && archive_entry_size(entry) > 0) {
            error = "Unexpected data attached to non-file entry: " + info->relative.string();
            break;
        }
        std::uint64_t bytes_read = 0;
        la_ssize_t n = 0;
        while ((n = archive_read_data(a, buffer.data(), buffer.size())) > 0) {
            bytes_read += static_cast<std::uint64_t>(n);
            if (info->filetype == AE_IFREG &&
                bytes_read > static_cast<std::uint64_t>(archive_entry_size(entry))) {
                error = "Archive file exceeds advertised size: " + info->relative.string();
                break;
            }
        }
        if (!error.empty()) break;
        if (n < 0) { error = archive_error(a, "Unreadable archive payload: "); break; }
        if (info->filetype == AE_IFREG &&
            bytes_read != static_cast<std::uint64_t>(archive_entry_size(entry))) {
            error = "Archive file ended before advertised size: " + info->relative.string();
            break;
        }
    }
    if (error.empty() && code != ARCHIVE_EOF)
        error = archive_error(a, "Truncated or invalid archive: ");
    if (error.empty() && report.entries == 0) error = "Archive has no entries";
    // Never create files through an archive-supplied symlink, no matter
    // whether the symlink appeared before or after the file in the tar.
    if (error.empty()) {
        for (const auto& path : seen) {
            auto parent = path.parent_path();
            while (!parent.empty()) {
                if (links.contains(parent)) {
                    error = "Archive contains entries below a symlink: " + path.string();
                    break;
                }
                parent = parent.parent_path();
            }
            if (!error.empty()) break;
        }
    }
    int close_status = archive_read_close(a);
    archive_read_free(a);
    if (!error.empty()) return std::unexpected(error);
    if (close_status != ARCHIVE_OK) return std::unexpected("Cannot close archive cleanly");
    return report;
}

struct StageGuard {
    fs::path path;
    ~StageGuard() {
        if (!path.empty()) {
            std::error_code ignored;
            fs::remove_all(path, ignored);
        }
    }
};

std::expected<fs::path, std::string> create_stage(const fs::path& parent, const fs::path& dest) {
    std::random_device rd;
    for (int attempt = 0; attempt < 32; ++attempt) {
        const auto nonce = (static_cast<unsigned long long>(rd()) << 32) | rd();
        fs::path stage = parent / (".securevault-restore-" + dest.filename().string() + "-" + std::to_string(nonce));
        std::error_code ec;
        if (fs::create_directory(stage, ec)) {
            fs::permissions(stage, fs::perms::owner_all, fs::perm_options::replace, ec);
            if (ec) {
                fs::remove(stage);
                return std::unexpected("Cannot secure staging directory: " + ec.message());
            }
            return stage;
        }
        if (ec && ec != std::errc::file_exists)
            return std::unexpected("Cannot create staging directory: " + ec.message());
    }
    return std::unexpected("Cannot allocate an unused staging directory");
}

std::expected<void, std::string> extract_entries(const std::string& archive_path, const fs::path& stage) {
    auto opened = open_archive(archive_path);
    if (!opened) return std::unexpected(opened.error());
    struct archive* a = *opened;
    archive_entry* entry = nullptr;
    std::vector<std::pair<fs::path, int>> directory_modes;
    std::array<char, buffer_size> buffer{};
    int code = ARCHIVE_OK;
    std::string error;
    while ((code = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        auto info = validate_entry(entry);
        if (!info) { error = info.error(); break; }
        const fs::path output = stage / info->relative;
        std::error_code ec;
        fs::create_directories(output.parent_path(), ec);
        if (ec) { error = "Cannot create restore parent directory: " + ec.message(); break; }
        if (fs::exists(output, ec) || fs::is_symlink(output, ec)) {
            if (info->filetype != AE_IFDIR || !fs::is_directory(output, ec)) {
                error = "Restore entry already exists: " + info->relative.string(); break;
            }
        }
        if (info->filetype == AE_IFDIR) {
            fs::create_directories(output, ec);
            if (ec) { error = "Cannot create directory: " + ec.message(); break; }
            directory_modes.emplace_back(output, info->mode);
        } else if (info->filetype == AE_IFLNK) {
            fs::create_symlink(archive_entry_symlink(entry), output, ec);
            if (ec) { error = "Cannot restore symlink: " + ec.message(); break; }
        } else {
            std::ofstream stream(output, std::ios::binary | std::ios::trunc);
            if (!stream) { error = "Cannot create restored file: " + output.string(); break; }
            std::uint64_t total = 0;
            la_ssize_t n = 0;
            while ((n = archive_read_data(a, buffer.data(), buffer.size())) > 0) {
                stream.write(buffer.data(), n);
                total += static_cast<std::uint64_t>(n);
                if (!stream) break;
            }
            stream.close();
            if (n < 0 || !stream || total != static_cast<std::uint64_t>(archive_entry_size(entry))) {
                error = "Failed to restore complete file: " + info->relative.string(); break;
            }
            fs::permissions(output, static_cast<fs::perms>(info->mode), fs::perm_options::replace, ec);
            if (ec) { error = "Cannot restore file permissions: " + ec.message(); break; }
        }
    }
    if (error.empty() && code != ARCHIVE_EOF)
        error = archive_error(a, "Extraction failed on archive: ");
    int close_status = archive_read_close(a);
    archive_read_free(a);
    if (!error.empty()) return std::unexpected(error);
    if (close_status != ARCHIVE_OK) return std::unexpected("Archive reader close failed");
    // Postpone read-only directory modes until after file creation.
    std::sort(directory_modes.begin(), directory_modes.end(), [](const auto& a, const auto& b) {
        return std::distance(a.first.begin(), a.first.end()) > std::distance(b.first.begin(), b.first.end());
    });
    for (const auto& [path, mode] : directory_modes) {
        std::error_code ec;
        fs::permissions(path, static_cast<fs::perms>(mode), fs::perm_options::replace, ec);
        if (ec) return std::unexpected("Cannot restore directory permissions: " + ec.message());
    }
    return {};
}
} // namespace

std::expected<ArchiveReport, std::string> verify_archive(const std::string& archive_path) {
    return scan_archive(archive_path);
}

std::expected<ArchiveReport, std::string> restore_archive(
    const std::string& archive_path, const std::string& destination) {
    auto verified = scan_archive(archive_path);
    if (!verified) return std::unexpected(verified.error());
    fs::path target = fs::absolute(destination).lexically_normal();
    if (target == target.root_path() || target.filename().empty())
        return std::unexpected("Restore destination must be a new non-root directory");
    std::error_code ec;
    if (fs::exists(target, ec) || fs::is_symlink(target, ec))
        return std::unexpected("Restore destination already exists; refusing overwrite: " + target.string());
    auto parent = target.parent_path();
    if (!fs::is_directory(parent, ec))
        return std::unexpected("Restore parent must already exist: " + parent.string());
    auto stage = create_stage(parent, target);
    if (!stage) return std::unexpected(stage.error());
    StageGuard guard{*stage};
    auto extracted = extract_entries(archive_path, *stage);
    if (!extracted) return std::unexpected(extracted.error());
    if (fs::exists(target, ec) || fs::is_symlink(target, ec))
        return std::unexpected("Restore destination appeared during extraction; refusing overwrite");
    fs::rename(*stage, target, ec);
    if (ec) return std::unexpected("Cannot publish restored directory: " + ec.message());
    guard.path.clear();
    return verified;
}
