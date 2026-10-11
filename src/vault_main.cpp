#include "vault.hpp"
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <string_view>

int main(int argc, char** argv) {
    static const std::map<std::string, std::set<std::string>> allowed = {
        {"init", {"--repo"}},
        {"create", {"--repo", "--source", "--password-file"}},
        {"database-backup", {"--repo", "--database", "--password-file"}},
        {"restore", {"--snapshot", "--target", "--password-file"}},
        {"verify", {"--snapshot", "--password-file"}},
        {"list", {"--repo"}},
        {"upload", {"--snapshot", "--password-file", "--url-file", "--ca-file"}},
        {"download", {"--repo", "--snapshot-id", "--password-file",
                      "--url-file", "--ca-file"}}
    };
    if (argc < 2 || !allowed.contains(argv[1])) {
        std::cerr << "Usage: securevault-vault "
                     "<init|create|database-backup|restore|verify|list|upload|download> "
                     "[documented --option VALUE pairs]\n";
        return 2;
    }
    const std::string action = argv[1];
    std::map<std::string, std::string> opts;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc || !allowed.at(action).contains(argv[i]) ||
            std::string_view(argv[i + 1]).starts_with("--") ||
            std::string_view(argv[i + 1]).empty() ||
            !opts.emplace(argv[i], argv[i + 1]).second) {
            std::cerr << "Invalid, duplicate or missing CLI option\n";
            return 2;
        }
    }
    for (const auto& key : allowed.at(action)) {
        if (key != "--ca-file" && !opts.contains(key)) {
            std::cerr << "Missing required CLI option: " << key << '\n';
            return 2;
        }
    }
    auto get = [&](const char* name) -> std::string {
        auto it = opts.find(name);
        return it == opts.end() ? "" : it->second;
    };
    if (action == "init") {
        auto result = securevault::vault::initialize(get("--repo"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << "Private native repository initialized\n";
    } else if (action == "create") {
        auto result = securevault::vault::create(
            get("--repo"), get("--source"), get("--password-file"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << result->string() << '\n';
    } else if (action == "database-backup") {
        auto result = securevault::vault::create_logical_dump(
            get("--repo"), get("--password-file"), get("--database"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << result->string() << '\n';
    } else if (action == "restore") {
        auto result = securevault::vault::restore(
            get("--snapshot"), get("--target"), get("--password-file"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << "Authenticated and restored to " << get("--target") << '\n';
    } else if (action == "upload") {
        auto result = securevault::vault::upload_https(
            get("--snapshot"), get("--password-file"), get("--url-file"),
            get("--ca-file"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << "Encrypted snapshot uploaded over verified HTTPS\n";
    } else if (action == "download") {
        auto result = securevault::vault::download_https(
            get("--repo"), get("--snapshot-id"), get("--password-file"),
            get("--url-file"), get("--ca-file"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << result->string() << '\n';
    } else if (action == "verify") {
        auto result = securevault::vault::verify(
            get("--snapshot"), get("--password-file"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << "AES-256-GCM authentication successful\n";
    } else if (action == "list") {
        auto result = securevault::vault::list(get("--repo"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        for (const auto& path : *result) std::cout << path.string() << '\n';
    }
    return 0;
}
