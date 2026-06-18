#include "backup.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <format>
#include <filesystem>
#include <vector>
#include <optional>
#include <system_error>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <zlib.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
#include <cstdlib>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {

struct TemporaryFileGuard {
    fs::path path;

    ~TemporaryFileGuard() {
        if (!path.empty()) {
            std::error_code ec;
            fs::remove(path, ec);
        }
    }
};

bool containsLineBreak(const std::string& value) {
    return value.find('\n') != std::string::npos || value.find('\r') != std::string::npos;
}

std::string escapePgPassField(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (char ch : value) {
        if (ch == ':' || ch == '\\') {
            escaped.push_back('\\');
        }
        escaped.push_back(ch);
    }
    return escaped;
}

std::expected<fs::path, std::string> createSecureTempFile(const std::string& prefix,
                                                          const std::string& extension,
                                                          const std::string& content) {
    std::error_code ec;
    const fs::path tempDir = fs::temp_directory_path(ec);
    if (ec) {
        return std::unexpected(std::format("Failed to resolve temp directory: {}", ec.message()));
    }

    const auto nowNanos = std::chrono::steady_clock::now().time_since_epoch().count();
    for (int attempt = 0; attempt < 16; ++attempt) {
        fs::path candidate = tempDir / std::format("{}-{}-{}.{}", prefix, nowNanos, attempt, extension);
        if (fs::exists(candidate, ec)) {
            if (ec) {
                return std::unexpected(std::format("Failed to check temp file existence: {}", ec.message()));
            }
            continue;
        }

        std::ofstream out(candidate, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            continue;
        }
        out.write(content.data(), static_cast<std::streamsize>(content.size()));
        out.close();
        if (!out) {
            fs::remove(candidate, ec);
            continue;
        }

#ifndef _WIN32
        fs::permissions(candidate,
                        fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace,
                        ec);
        if (ec) {
            fs::remove(candidate, ec);
            return std::unexpected(std::format("Failed to set secure temp file permissions: {}", ec.message()));
        }
#endif

        return candidate;
    }

    return std::unexpected("Failed to create secure temp credentials file");
}

std::expected<void, std::string> runCommandWithRedirect(
    const std::vector<std::string>& args,
    const fs::path& stdoutPath,
    const std::optional<std::pair<std::string, std::string>>& envVar = std::nullopt) {
    if (args.empty()) {
        return std::unexpected("No command provided");
    }

#ifdef _WIN32
    int outputFd = _open(stdoutPath.string().c_str(),
                         _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
                         _S_IREAD | _S_IWRITE);
    if (outputFd == -1) {
        return std::unexpected(std::format("Failed to open dump output file: {}", std::strerror(errno)));
    }

    int savedStdoutFd = _dup(_fileno(stdout));
    if (savedStdoutFd == -1) {
        _close(outputFd);
        return std::unexpected(std::format("Failed to duplicate stdout: {}", std::strerror(errno)));
    }

    if (_dup2(outputFd, _fileno(stdout)) == -1) {
        _close(outputFd);
        _close(savedStdoutFd);
        return std::unexpected(std::format("Failed to redirect stdout: {}", std::strerror(errno)));
    }
    _close(outputFd);

    std::optional<std::string> originalEnv;
    if (envVar) {
        if (const char* existing = std::getenv(envVar->first.c_str())) {
            originalEnv = existing;
        }
        if (_putenv_s(envVar->first.c_str(), envVar->second.c_str()) != 0) {
            _dup2(savedStdoutFd, _fileno(stdout));
            _close(savedStdoutFd);
            return std::unexpected(std::format("Failed to set environment variable {}", envVar->first));
        }
    }

    std::vector<const char*> argv;
    argv.reserve(args.size() + 1);
    for (const auto& arg : args) {
        argv.push_back(arg.c_str());
    }
    argv.push_back(nullptr);

    const int rc = _spawnvp(_P_WAIT, args[0].c_str(), argv.data());
    std::fflush(stdout);
    _dup2(savedStdoutFd, _fileno(stdout));
    _close(savedStdoutFd);

    if (envVar) {
        if (originalEnv) {
            _putenv_s(envVar->first.c_str(), originalEnv->c_str());
        } else {
            _putenv_s(envVar->first.c_str(), "");
        }
    }

    if (rc == -1) {
        return std::unexpected(std::format("Failed to execute {}: {}", args[0], std::strerror(errno)));
    }
    if (rc != 0) {
        return std::unexpected(std::format("{} exited with status {}", args[0], rc));
    }
    return {};
#else
    int outputFd = ::open(stdoutPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (outputFd == -1) {
        return std::unexpected(std::format("Failed to open dump output file: {}", std::strerror(errno)));
    }

    const pid_t pid = ::fork();
    if (pid == -1) {
        ::close(outputFd);
        return std::unexpected(std::format("Failed to fork process: {}", std::strerror(errno)));
    }

    if (pid == 0) {
        if (::dup2(outputFd, STDOUT_FILENO) == -1) {
            _exit(127);
        }
        ::close(outputFd);

        if (envVar && ::setenv(envVar->first.c_str(), envVar->second.c_str(), 1) != 0) {
            _exit(127);
        }

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        _exit(127);
    }

    ::close(outputFd);

    int status = 0;
    if (::waitpid(pid, &status, 0) == -1) {
        return std::unexpected(std::format("Failed to wait for {}: {}", args[0], std::strerror(errno)));
    }
    if (!WIFEXITED(status)) {
        return std::unexpected(std::format("{} terminated unexpectedly", args[0]));
    }
    if (WEXITSTATUS(status) != 0) {
        return std::unexpected(std::format("{} exited with status {}", args[0], WEXITSTATUS(status)));
    }
    return {};
#endif
}

std::expected<std::string, std::string> compressSqlDump(const std::string& label,
                                                        const fs::path& tempSqlPath,
                                                        const std::string& outputPath) {
    std::ifstream inFile(tempSqlPath, std::ios::binary);
    if (!inFile.is_open()) {
        return std::unexpected(std::format("Failed to open temporary SQL dump for {}", label));
    }

    const std::string dbBackupFileGz = std::format("{}.sql.gz", outputPath);
    gzFile outFile = gzopen(dbBackupFileGz.c_str(), "wb");
    if (!outFile) {
        return std::unexpected(std::format("Failed to open gzip file for {} backup", label));
    }

    char buf[8192];
    while (inFile) {
        inFile.read(buf, sizeof(buf));
        const std::streamsize bytesRead = inFile.gcount();
        if (bytesRead <= 0) {
            continue;
        }

        const int written = gzwrite(outFile, buf, static_cast<unsigned int>(bytesRead));
        if (written == 0 || written != bytesRead) {
            const int zerr = gzclose(outFile);
            (void)zerr;
            return std::unexpected(std::format("Failed to write compressed {} backup", label));
        }
    }

    if (inFile.bad()) {
        const int zerr = gzclose(outFile);
        (void)zerr;
        return std::unexpected(std::format("Failed while reading SQL dump for {}", label));
    }

    if (gzclose(outFile) != Z_OK) {
        return std::unexpected(std::format("Failed to finalize compressed {} backup", label));
    }

    return dbBackupFileGz;
}

} // namespace

MySQLBackupStrategy::MySQLBackupStrategy(const std::string& user, std::optional<std::string> password)
    : user(user), password(password) {}

std::expected<std::string, std::string> MySQLBackupStrategy::execute(const std::string& outputPath) {
    const bool hasPassword = password.has_value() && !password->empty();
    if (user.empty()) {
        return std::unexpected("Invalid MySQL credentials: user is missing");
    }

    fs::path outputFilePath(outputPath);
    std::error_code ec;
    fs::create_directories(outputFilePath.parent_path(), ec);
    if (ec) {
        return std::unexpected(std::format("Failed to create output directory: {}", ec.message()));
    }

#ifdef _WIN32
    const std::string mysqldump = "mysqldump.exe";
#else
    const std::string mysqldump = "mysqldump";
#endif

    const fs::path tempSqlPath = fs::path(std::format("{}.sql", outputPath));
    TemporaryFileGuard tempSqlGuard{tempSqlPath};

    std::optional<TemporaryFileGuard> defaultsFileGuard;
    if (hasPassword) {
        if (containsLineBreak(*password)) {
            return std::unexpected("MySQL password contains unsupported line breaks");
        }

        auto defaultsPathResult = createSecureTempFile(
            "securevault-mysql",
            "cnf",
            std::format("[client]\npassword={}\n", *password));
        if (!defaultsPathResult) {
            return std::unexpected(defaultsPathResult.error());
        }
        defaultsFileGuard = TemporaryFileGuard{*defaultsPathResult};
    }

    std::vector<std::string> args = {mysqldump};
    if (defaultsFileGuard) {
        args.push_back(std::format("--defaults-extra-file={}", defaultsFileGuard->path.string()));
    }
    args.emplace_back("-u");
    args.emplace_back(user);
    args.emplace_back("--all-databases");

    std::cout << "Backing up all MySQL databases..." << std::endl;
    std::cout << "Executing mysqldump..." << std::flush;
    auto runResult = runCommandWithRedirect(args, tempSqlPath);
    if (!runResult) {
        return std::unexpected(std::format("Failed to execute mysqldump: {}", runResult.error()));
    }

    std::cout << "\nCompressing database backup..." << std::endl;
    auto compressed = compressSqlDump("MySQL", tempSqlPath, outputPath);
    if (!compressed) {
        return std::unexpected(compressed.error());
    }

    std::cout << "MySQL backup completed: " << *compressed << std::endl;
    return *compressed;
}

PostgreSQLBackupStrategy::PostgreSQLBackupStrategy(const std::string& user, std::optional<std::string> password, const std::string& host, int port)
    : user(user), password(password), host(host), port(port) {}

std::expected<std::string, std::string> PostgreSQLBackupStrategy::execute(const std::string& outputPath) {
    const bool hasPassword = password.has_value() && !password->empty();
    if (user.empty() || host.empty() || port <= 0) {
        return std::unexpected("Invalid PostgreSQL credentials: user, host, or port missing");
    }

    fs::path outputFilePath(outputPath);
    std::error_code ec;
    fs::create_directories(outputFilePath.parent_path(), ec);
    if (ec) {
        return std::unexpected(std::format("Failed to create output directory: {}", ec.message()));
    }

#ifdef _WIN32
    const std::string pgdumpall = "pg_dumpall.exe";
#else
    const std::string pgdumpall = "pg_dumpall";
#endif

    const fs::path tempSqlPath = fs::path(std::format("{}.sql", outputPath));
    TemporaryFileGuard tempSqlGuard{tempSqlPath};

    std::optional<TemporaryFileGuard> pgpassFileGuard;
    std::optional<std::pair<std::string, std::string>> envVar;
    if (hasPassword) {
        if (containsLineBreak(*password)) {
            return std::unexpected("PostgreSQL password contains unsupported line breaks");
        }

        const std::string pgpassLine = std::format("{}:{}:*:{}:{}\n",
                                                    escapePgPassField(host),
                                                    port,
                                                    escapePgPassField(user),
                                                    escapePgPassField(*password));
        auto pgpassPathResult = createSecureTempFile("securevault-pg", "pass", pgpassLine);
        if (!pgpassPathResult) {
            return std::unexpected(pgpassPathResult.error());
        }

        pgpassFileGuard = TemporaryFileGuard{*pgpassPathResult};
        envVar = std::make_pair(std::string("PGPASSFILE"), pgpassFileGuard->path.string());
    }

    std::vector<std::string> args = {
        pgdumpall,
        "-U", user,
        "-h", host,
        "-p", std::to_string(port)
    };

    std::cout << "Backing up all PostgreSQL databases..." << std::endl;
    std::cout << "Executing pg_dumpall..." << std::flush;
    auto runResult = runCommandWithRedirect(args, tempSqlPath, envVar);
    if (!runResult) {
        return std::unexpected(std::format("Failed to execute pg_dumpall: {}", runResult.error()));
    }

    std::cout << "\nCompressing database backup..." << std::endl;
    auto compressed = compressSqlDump("PostgreSQL", tempSqlPath, outputPath);
    if (!compressed) {
        return std::unexpected(compressed.error());
    }

    std::cout << "PostgreSQL backup completed: " << *compressed << std::endl;
    return *compressed;
}
