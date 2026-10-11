#include "operations.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <cctype>
#include <optional>
#include <random>
#include <regex>
#include <set>
#include <sstream>
#include <system_error>
#ifdef _WIN32
#include <windows.h>
#else
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <sys/stdio.h>
#endif
#endif

namespace securevault::ops {
namespace {
constexpr std::size_t output_cap = 16 * 1024 * 1024;
bool valid_snapshot(std::string_view v) {
    return v.size() == 64 && std::all_of(v.begin(), v.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}
bool is_remote(std::string_view name) {
    for (const auto* prefix : {"s3:", "sftp:", "rest:", "rclone:", "b2:", "gs:", "azure:", "swift:"}) {
        if (name.starts_with(prefix)) return true;
    }
    return false;
}
bool is_safe_destination(const fs::path& path) {
    if (!path.is_absolute() || path == path.root_path() || path.filename().empty()) return false;
    std::error_code ec;
    if (fs::exists(path, ec) || fs::is_symlink(fs::symlink_status(path, ec))) return false;
    if (!fs::is_directory(path.parent_path(), ec) ||
        fs::is_symlink(fs::symlink_status(path.parent_path(), ec))) return false;
    for (auto part : path) if (part == "..") return false;
    return true;
}
struct Stage {
    fs::path path;
    Stage(fs::path value) : path(std::move(value)) {}
    Stage(const Stage&) = delete;
    Stage& operator=(const Stage&) = delete;
    Stage(Stage&& other) noexcept : path(std::move(other.path)) { other.path.clear(); }
    Stage& operator=(Stage&&) = delete;
    ~Stage() {
        std::error_code ignored;
        if (!path.empty()) fs::remove_all(path, ignored);
    }
};
std::expected<Stage, std::string> make_stage(const fs::path& target) {
#ifndef _WIN32
    const auto pattern = (target.parent_path() / ".securevault-stage-XXXXXX").string();
    std::vector<char> buffer(pattern.begin(), pattern.end());
    buffer.push_back(0);
    if (!mkdtemp(buffer.data())) return std::unexpected("Unable to create private staging directory");
    return Stage{fs::path(buffer.data())};
#else
    return std::unexpected("Atomic private staging not implemented for Windows");
#endif
}
std::expected<void, std::string> exclusive_publish(const fs::path& from, const fs::path& to) {
#if defined(__linux__)
    const int rc = static_cast<int>(syscall(SYS_renameat2, AT_FDCWD, from.c_str(),
                                            AT_FDCWD, to.c_str(), 1)); // RENAME_NOREPLACE
#elif defined(__APPLE__)
    const int rc = renamex_np(from.c_str(), to.c_str(), RENAME_EXCL);
#else
    return std::unexpected("Atomic no-overwrite publish unavailable on this platform");
#endif
#if defined(__linux__) || defined(__APPLE__)
    if (rc != 0) return std::unexpected("Exclusive directory publish failed (destination exists or permission denied)");
    return {};
#endif
}
std::expected<void, std::string> safe_restored_tree(const fs::path& stage) {
    std::error_code ec;
    // Compare paths in the SAME namespace. On macOS /var is commonly a
    // symlink to /private/var: weakly_canonical(stage) would change that
    // prefix, while recursive_directory_iterator returns the original
    // /var-based paths. The mismatch falsely rejects safe relative links.
    // The stage is an absolute private directory; do not follow restored
    // symlinks and only perform lexical containment checks within it.
    const auto root = stage.lexically_normal();
    if (!root.is_absolute()) return std::unexpected("Extraction root must be absolute");

    // Do not follow directory symlinks. Restic restores metadata too, so
    // reject devices, sockets, FIFOs, and hardlinks before publishing files.
    fs::recursive_directory_iterator it(stage, fs::directory_options::none, ec);
    if (ec) return std::unexpected("Cannot traverse recovered directory");
    const fs::recursive_directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec) return std::unexpected("Cannot inspect entire recovered tree");
        const auto status = it->symlink_status(ec);
        if (ec) return std::unexpected("Cannot inspect restored entry metadata");
        if (fs::is_regular_file(status)) {
            const auto links = fs::hard_link_count(it->path(), ec);
            if (ec || links != 1)
                return std::unexpected("Hardlinked restored files are refused");
            continue;
        }
        if (fs::is_directory(status)) continue;
        if (!fs::is_symlink(status))
            return std::unexpected("Special files in a restored snapshot are refused");

        const auto target = fs::read_symlink(it->path(), ec);
        if (ec || target.empty() || target.is_absolute())
            return std::unexpected("Restored symlink has unsafe target");
        const auto resolved = (it->path().parent_path() / target).lexically_normal();
        const auto rel = resolved.lexically_relative(root);
        if (rel.empty() || rel == "." || (*rel.begin()) == "..")
            return std::unexpected("Restored symlink escapes recovery directory");
    }
    if (ec) return std::unexpected("Cannot inspect entire recovered tree");
    return {};
}
std::expected<Json::Value, std::string> snapshots() {
    auto r = execute({"restic", "snapshots", "--json", "--tag", "securevault"}, true, std::chrono::seconds{300});
    if (!r || r->exit_code) return std::unexpected("Restic inventory failed");
    auto j = parse_json(r->out);
    if (!j || !j->isArray()) return std::unexpected("Restic inventory JSON invalid");
    Json::Value safe(Json::arrayValue);
    for (const auto& item : *j) {
        if (!item.isObject() || !valid_snapshot(item.get("id", "").asString()) ||
            !item["tags"].isArray()) continue;
        bool marker = false;
        int kinds = 0;
        for (const auto& tag : item["tags"]) {
            if (!tag.isString()) continue;
            if (tag.asString() == "securevault") marker = true;
            if (tag.asString() == "files" || tag.asString() == "mariadb" ||
                tag.asString() == "postgresql" ||
                tag.asString() == "generation-committed") ++kinds;
        }
        if (marker && kinds == 1) safe.append(item);
    }
    return safe;
}
bool tagged(const Json::Value& item, std::string_view tag) {
    for (const auto& v : item["tags"]) if (v.isString() && v.asString() == tag) return true;
    return false;
}
} // namespace

std::expected<Json::Value, std::string> parse_json(std::string_view s) {
    Json::CharReaderBuilder b;
    b["collectComments"] = false;
    Json::Value root;
    std::string errors;
    auto reader = std::unique_ptr<Json::CharReader>(b.newCharReader());
    if (!reader->parse(s.data(), s.data() + s.size(), &root, &errors))
        return std::unexpected("Invalid JSON returned by an external tool");
    return root;
}
Json::Value error_json(const std::string& message) {
    Json::Value v;
    v["error"] = message;
    return v;
}
bool has_tool(const std::string& name) {
    if (name.empty() || name.find('/') != std::string::npos) return false;
    const char* env = std::getenv("PATH");
    if (!env) return false;
    std::stringstream paths(env);
    std::string dir;
    while (std::getline(paths, dir, ':')) {
        if (dir.empty()) continue;
        std::error_code ec;
        auto p = fs::path(dir) / name;
#ifndef _WIN32
        if (fs::is_regular_file(p, ec) && access(p.c_str(), X_OK) == 0) return true;
#else
        if (fs::is_regular_file(p, ec)) return true;
#endif
    }
    return false;
}
std::expected<ProcessResult, std::string> execute(
    const std::vector<std::string>& args, bool capture, std::chrono::seconds timeout) {
#ifdef _WIN32
    return std::unexpected("External process runner requires a POSIX platform");
#else
    if (args.empty() || timeout <= std::chrono::seconds::zero())
        return std::unexpected("Invalid external process arguments or timeout");
    int fds[2] = {-1, -1};
    if (capture && pipe(fds) != 0)
        return std::unexpected("Cannot open process output pipe");
    const pid_t pid = fork();
    if (pid < 0) {
        if (capture) { close(fds[0]); close(fds[1]); }
        return std::unexpected("Cannot create child process");
    }
    if (pid == 0) {
        // A private process group lets a timeout stop descendants too.
        setpgid(0, 0);
        if (capture) {
            close(fds[0]);
            if (dup2(fds[1], STDOUT_FILENO) < 0) _exit(127);
            close(fds[1]);
        } else {
            const int null_fd = open("/dev/null", O_WRONLY);
            if (null_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0) _exit(127);
            close(null_fd);
        }
        const int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd < 0 || dup2(null_fd, STDERR_FILENO) < 0) _exit(127);
        close(null_fd);
        std::vector<char*> argv;
        for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
        argv.push_back(nullptr);
        execvp(argv[0], argv.data());
        _exit(127);
    }
    // The child attempts the same operation; harmless if it already exec'd.
    setpgid(pid, pid);
    if (capture) close(fds[1]);
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    std::string output;
    std::array<char, 8192> buffer{};
    bool eof = !capture, reaped = false;
    int status = 0;
    std::string error;
    while (!reaped || !eof) {
        if (!reaped) {
            const pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid) reaped = true;
            else if (waited < 0 && errno != EINTR) {
                error = "Cannot wait for external process";
                break;
            }
        }
        if (reaped && eof) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            error = "External command timed out";
            break;
        }
        if (!eof) {
            pollfd reader{fds[0], static_cast<short>(POLLIN | POLLHUP), 0};
            const int ready = poll(&reader, 1, 25);
            if (ready < 0 && errno != EINTR) {
                error = "Cannot read external command output";
                break;
            }
            if (ready > 0 && (reader.revents & (POLLIN | POLLHUP | POLLERR))) {
                const ssize_t count = read(fds[0], buffer.data(), buffer.size());
                if (count == 0) eof = true;
                else if (count < 0 && errno != EINTR) {
                    error = "Cannot read external command output";
                    break;
                } else if (count > 0) {
                    const auto size = static_cast<std::size_t>(count);
                    if (size > output_cap - output.size()) {
                        error = "External command output exceeded limit";
                        break;
                    }
                    output.append(buffer.data(), size);
                }
            }
        } else {
            // The process may have no captured stdout; still enforce deadline.
            poll(nullptr, 0, 25);
        }
    }
    if (!error.empty()) {
        // A child cannot be allowed to keep running after a failed backup.
        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
    }
    if (capture) close(fds[0]);
    if (!reaped) {
        pid_t waited;
        do { waited = waitpid(pid, &status, 0); }
        while (waited < 0 && errno == EINTR);
        if (waited < 0 && error.empty()) error = "Cannot reap external process";
    }
    if (!error.empty()) return std::unexpected(error);
    return ProcessResult{WIFEXITED(status) ? WEXITSTATUS(status) : 128, std::move(output)};
#endif
}
std::expected<void, std::string> pipe_processes(
    const std::vector<std::string>& producer, const std::vector<std::string>& consumer,
    std::chrono::seconds timeout) {
#ifdef _WIN32
    return std::unexpected("Streaming requires a POSIX platform");
#else
    if (producer.empty() || consumer.empty() || timeout <= std::chrono::seconds::zero())
        return std::unexpected("Invalid streaming command or timeout");
    int p[2];
    if (pipe(p) != 0) return std::unexpected("Cannot create streaming pipe");
    auto launch = [&](const std::vector<std::string>& args, bool src) -> pid_t {
        const pid_t pid = fork();
        if (pid == 0) {
            setpgid(0, 0);
            if (dup2(src ? p[1] : p[0], src ? STDOUT_FILENO : STDIN_FILENO) < 0)
                _exit(127);
            close(p[0]); close(p[1]);
            const int null_fd = open("/dev/null", O_WRONLY);
            if (null_fd < 0 || dup2(null_fd, STDERR_FILENO) < 0) _exit(127);
            close(null_fd);
            std::vector<char*> argv;
            for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
            argv.push_back(nullptr);
            execvp(argv[0], argv.data());
            _exit(127);
        }
        if (pid > 0) setpgid(pid, pid);
        return pid;
    };
    const pid_t first = launch(producer, true);
    const pid_t second = first > 0 ? launch(consumer, false) : -1;
    close(p[0]); close(p[1]);
    auto stop = [](pid_t pid) {
        if (pid > 0) {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
        }
    };
    if (first <= 0 || second <= 0) {
        stop(first);
        int status = 0;
        if (first > 0) {
            pid_t waited;
            do { waited = waitpid(first, &status, 0); }
            while (waited < 0 && errno == EINTR);
        }
        return std::unexpected("Cannot launch both streaming subprocesses");
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    bool first_done = false, second_done = false;
    bool error = false, expired = false;
    int a = 0, b = 0;
    auto wait_one = [&](pid_t pid, bool& done, int& status) {
        if (done) return;
        const pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            done = true;
            if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) error = true;
        } else if (waited < 0 && errno != EINTR) {
            done = true;
            error = true;
        }
    };
    while (!first_done || !second_done) {
        wait_one(first, first_done, a);
        wait_one(second, second_done, b);
        if (error) break;
        if (std::chrono::steady_clock::now() >= deadline) {
            expired = true;
            break;
        }
        if (!first_done || !second_done) poll(nullptr, 0, 25);
    }
    if (error || expired) {
        if (!first_done) stop(first);
        if (!second_done) stop(second);
    }
    auto reap = [](pid_t pid, bool done) {
        if (done) return;
        int status = 0;
        pid_t waited;
        do { waited = waitpid(pid, &status, 0); }
        while (waited < 0 && errno == EINTR);
    };
    reap(first, first_done);
    reap(second, second_done);
    if (expired)
        return std::unexpected("Streaming backup timed out; incomplete generation refused");
    if (error)
        return std::unexpected("Streaming database backup failed; incomplete generation refused");
    return {};
#endif
}
std::expected<void, std::string> private_file(const fs::path& path) {
    std::error_code ec;
    const auto st = fs::symlink_status(path, ec);
    if (ec || !fs::is_regular_file(st) || fs::is_symlink(st))
        return std::unexpected("Secret must be a regular, non-symlink file");
#ifndef _WIN32
    if ((static_cast<unsigned>(st.permissions()) & 077) != 0)
        return std::unexpected("Secret has insecure permissions");
#endif
    return {};
}
std::expected<void, std::string> remote_restic() {
    const char* repo = std::getenv("RESTIC_REPOSITORY");
    const char* pass = std::getenv("RESTIC_PASSWORD_FILE");
    if (!repo || !is_remote(repo)) return std::unexpected("Independent remote RESTIC_REPOSITORY required");
    if (!pass || !*pass) return std::unexpected("RESTIC_PASSWORD_FILE required");
    auto secret = private_file(pass);
    if (!secret) return std::unexpected(secret.error());
    if (!has_tool("restic")) return std::unexpected("restic binary unavailable");
    return {};
}
Result restic_list() {
    auto ready = remote_restic();
    if (!ready) return std::unexpected(ready.error());
    return snapshots();
}
Result restic_generations() {
    auto inventory = restic_list();
    if (!inventory) return inventory;
    std::map<std::string, std::set<std::string>, std::greater<>> generations;
    const std::regex stamp("^[0-9]{8}T[0-9]{6}Z$");
    for (const auto& snapshot : *inventory) {
        std::string gen;
        for (const auto& tag : snapshot["tags"]) {
            if (tag.isString() && std::regex_match(tag.asString(), stamp)) {
                gen = tag.asString();
                break;
            }
        }
        if (gen.empty()) continue;
        for (const auto& kind : {"files", "postgresql", "mariadb",
                                 "generation-committed"})
            if (tagged(snapshot, kind)) generations[gen].insert(kind);
    }
    Json::Value result(Json::arrayValue);
    for (const auto& [stamp, kinds] : generations) {
        Json::Value record;
        record["generation"] = stamp;
        // Three snapshots alone can exist after a failed dump/stream.
        // Only a final encrypted Restic commit marker makes a generation
        // eligible to be reported complete. Completeness is not integrity.
        record["committed"] = kinds.contains("generation-committed");
        record["status"] = kinds.size() == 4 ? "COMPLETE" : "INCOMPLETE";
        for (const auto& kind : kinds) record["kinds"].append(kind);
        result.append(record);
    }
    return result;
}
Result restic_check() {
    auto ready = remote_restic();
    if (!ready) return std::unexpected(ready.error());
    const auto result = execute({"restic", "check", "--read-data"}, false, std::chrono::hours{12});
    if (!result || result->exit_code) return std::unexpected("Restic repository data integrity check failed");
    Json::Value report;
    report["checked"] = true;
    report["read_all_data"] = true;
    return report;
}
Result restic_restore(const std::string& id, const std::string& kind,
                      const fs::path& destination, bool allow_plaintext) {
    auto ready = remote_restic();
    if (!ready) return std::unexpected(ready.error());
    if (!valid_snapshot(id)) return std::unexpected("Require complete 64-hex snapshot ID");
    if (kind != "files" && kind != "postgresql" && kind != "mariadb")
        return std::unexpected("Invalid snapshot kind");
    if (kind != "files" && !allow_plaintext)
        return std::unexpected("SQL export requires explicit --allow-plaintext-export");
    auto inventory = snapshots();
    if (!inventory) return std::unexpected(inventory.error());
    bool matched = false;
    for (const auto& item : *inventory)
        if (item["id"].asString() == id && tagged(item, kind)) matched = true;
    if (!matched) return std::unexpected("Snapshot not found with required SecureVault kind");
    if (!is_safe_destination(destination))
        return std::unexpected("Recovery target must be a new directory under a real existing parent");
    auto stage = make_stage(destination);
    if (!stage) return std::unexpected(stage.error());
    auto result = execute({"restic", "restore", id, "--target", stage->path.string()}, false, std::chrono::hours{12});
    if (!result || result->exit_code) return std::unexpected("Restic isolated restoration failed");
    auto safe = safe_restored_tree(stage->path);
    if (!safe) return std::unexpected(safe.error());
    std::error_code ec;
    if (fs::is_empty(stage->path, ec) || ec) return std::unexpected("Empty recovery rejected");
    if (kind != "files") {
        const auto expected = stage->path / (kind == "postgresql" ?
                                            "postgresql-all.sql" : "mariadb-all.sql");
        std::size_t count = 0;
        for (fs::recursive_directory_iterator i(stage->path), end; i != end; ++i) ++count;
        if (count != 1 || !fs::is_regular_file(expected, ec) ||
            fs::is_symlink(fs::symlink_status(expected, ec)))
            return std::unexpected("SQL export contains unexpected files");
        fs::permissions(expected, fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace, ec);
        if (ec) return std::unexpected("Cannot secure plaintext SQL export");
    }
    auto published = exclusive_publish(stage->path, destination);
    if (!published) return std::unexpected(published.error());
    stage->path.clear();
    Json::Value report;
    report["restored"] = true;
    report["kind"] = kind;
    report["target"] = destination.string();
    report["plaintext_sql"] = kind != "files";
    return report;
}
} // namespace securevault::ops
