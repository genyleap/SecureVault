#include <array>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

namespace fs = std::filesystem;
namespace {
struct Temp {
    fs::path root;
    Temp() {
        const auto pattern = (fs::temp_directory_path() / "securevault-cli-XXXXXX").string();
        std::vector<char> name(pattern.begin(), pattern.end());
        name.push_back('\0');
        if (!mkdtemp(name.data())) throw std::runtime_error("Cannot create CLI fixture");
        root = name.data();
    }
    ~Temp() { std::error_code ec; fs::remove_all(root, ec); }
};
struct Result { int code = -1; std::string output; };
Result invoke(const std::string& binary, std::vector<std::string> args) {
    int ends[2];
    if (pipe(ends) != 0) throw std::runtime_error("Cannot capture native CLI");
    const pid_t pid = fork();
    if (pid < 0) {
        close(ends[0]); close(ends[1]);
        throw std::runtime_error("Cannot fork native CLI test");
    }
    if (pid == 0) {
        close(ends[0]);
        if (dup2(ends[1], STDOUT_FILENO) < 0) _exit(127);
        close(ends[1]);
        int fd = open("/dev/null", O_WRONLY);
        if (fd >= 0) {
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(binary.c_str()));
        for (auto& argument : args) argv.push_back(argument.data());
        argv.push_back(nullptr);
        execv(binary.c_str(), argv.data());
        _exit(127);
    }
    close(ends[1]);
    Result result;
    std::array<char, 4096> bytes{};
    for (;;) {
        const ssize_t count = read(ends[0], bytes.data(), bytes.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) {
            close(ends[0]);
            throw std::runtime_error("Cannot read native CLI output");
        }
        if (count == 0) break;
        if (result.output.size() + static_cast<std::size_t>(count) > 16384) {
            close(ends[0]);
            throw std::runtime_error("Native CLI unexpectedly emitted excessive output");
        }
        result.output.append(bytes.data(), static_cast<std::size_t>(count));
    }
    close(ends[0]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); }
    while (waited < 0 && errno == EINTR);
    if (waited != pid) throw std::runtime_error("Cannot reap native CLI");
    result.code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    return result;
}
void require(bool accepted, std::string_view what) {
    if (!accepted) throw std::runtime_error(std::string(what));
}
void file(const fs::path& path, std::string_view data) {
    std::ofstream out(path, std::ios::binary);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    require(static_cast<bool>(out), "Cannot write test fixture");
}
std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}
}
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    try {
        const auto binary = fs::absolute(argv[1]).string();
        Temp temp;
        const auto repository = temp.root / "repository";
        const auto sample = temp.root / "sample";
        const auto pass = temp.root / "password";
        const auto target = temp.root / "recovered";
        const std::string data = "native C++23 CLI backup verification\n";
        fs::create_directory(sample);
        file(sample / "document.txt", data);
        file(pass, "local-test-password-beyond-16-bytes");
        require(chmod(pass.c_str(), 0600) == 0, "Cannot protect test password file");
        require(invoke(binary, {"bogus", "--repo", repository.string()}).code == 2,
                "Unknown CLI command must fail");
        require(invoke(binary, {"create", "--repo", repository.string()}).code == 2,
                "Required options must be explicit");
        require(invoke(binary, {"init", "--repo", repository.string(),
                                "--unexpected", "value"}).code == 2,
                "Undocumented CLI option must be rejected");
        require(invoke(binary, {"init", "--repo", repository.string()}).code == 0,
                "CLI repository initialization failed");
        require(invoke(binary, {"init", "--repo", repository.string()}).code != 0,
                "CLI must refuse to initialize existing repository");
        auto snapshot = invoke(binary, {"create", "--repo", repository.string(),
                         "--source", sample.string(), "--password-file", pass.string()});
        require(snapshot.code == 0, "Native CLI create failed");
        if (!snapshot.output.empty() && snapshot.output.back() == '\n')
            snapshot.output.pop_back();
        require(snapshot.output.size() > 69 && fs::exists(snapshot.output),
                "Native CLI must print created snapshot path");
        const auto listing = invoke(binary, {"list", "--repo", repository.string()});
        require(listing.code == 0 &&
                listing.output.find(snapshot.output) != std::string::npos,
                "Native CLI inventory must list published snapshot");
        require(invoke(binary, {"verify", "--snapshot", snapshot.output,
                                "--password-file", pass.string()}).code == 0,
                "Native CLI verify failed");
        require(invoke(binary, {"restore", "--snapshot", snapshot.output,
                                "--target", target.string(),
                                "--password-file", pass.string()}).code == 0,
                "Native CLI restore failed");
        require(read_file(target / "document.txt") == data,
                "Native CLI restored incorrect file bytes");
        require(invoke(binary, {"restore", "--snapshot", snapshot.output,
                                "--target", target.string(),
                                "--password-file", pass.string()}).code != 0,
                "Native CLI must never overwrite restore destination");
        std::cout << "SecureVault C++23 CLI: create, list, verify, restore, "
                     "validation and overwrite protection passed\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "SecureVault CLI regression failed: " << e.what() << '\n';
        return 1;
    }
}
