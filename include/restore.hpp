#pragma once

#include <cstdint>
#include <expected>
#include <string>

struct ArchiveReport {
    std::uint64_t entries = 0;
    std::uint64_t regular_bytes = 0;
};

// Verify all archive payloads and refuse path traversal and unsafe entry types.
std::expected<ArchiveReport, std::string> verify_archive(const std::string& archive_path);

// Restore to a new non-existent directory through an isolated staging directory.
std::expected<ArchiveReport, std::string> restore_archive(
    const std::string& archive_path, const std::string& destination);
