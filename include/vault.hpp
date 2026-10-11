#pragma once
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace securevault::vault {
namespace fs = std::filesystem;
using Status = std::expected<void, std::string>;
using Snapshot = std::expected<fs::path, std::string>;

// SVLT v1: authenticated, versioned, independent encrypted archive.
// No external backup executable or scripting runtime is required.
Status initialize(const fs::path& repository);
Snapshot create(const fs::path& repository, const fs::path& source,
                const fs::path& password_file);
Status verify(const fs::path& archive, const fs::path& password_file);
Status restore(const fs::path& archive, const fs::path& target,
               const fs::path& password_file);
std::expected<std::vector<fs::path>, std::string> list(const fs::path& repository);
}
