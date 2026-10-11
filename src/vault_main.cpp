#include "vault.hpp"
#include <iostream>
#include <map>
#include <string>
#include <string_view>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "Usage: securevault-vault <init|create|restore|verify|list> "
                     "--repo PATH --source PATH --snapshot PATH "
                     "--target PATH --password-file PATH\n";
        return 2;
    }
    const std::string action(argv[1]);
    std::map<std::string, std::string> opts;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc || !std::string_view(argv[i]).starts_with("--")) {
            std::cerr << "Invalid option\n";
            return 2;
        }
        const auto [it, ok] = opts.emplace(argv[i], argv[i + 1]);
        if (!ok) {
            std::cerr << "Duplicate argument\n";
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
    } else if (action == "restore") {
        auto result = securevault::vault::restore(
            get("--snapshot"), get("--target"), get("--password-file"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << "Authenticated and restored to " << get("--target") << '\n';
    } else if (action == "verify") {
        auto result = securevault::vault::verify(
            get("--snapshot"), get("--password-file"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        std::cout << "AES-256-GCM authentication successful\n";
    } else if (action == "list") {
        auto result = securevault::vault::list(get("--repo"));
        if (!result) { std::cerr << result.error() << '\n'; return 1; }
        for (const auto& file : *result) std::cout << file.string() << '\n';
    } else {
        std::cerr << "Unknown native vault operation\n";
        return 2;
    }
    return 0;
}
