#include "backup.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <format>
#include <cstdlib>
#include <filesystem>
#include <zlib.h>

namespace fs = std::filesystem;

MySQLBackupStrategy::MySQLBackupStrategy(const std::string& user, std::optional<std::string> password)
    : user(user), password(password) {}

std::expected<std::string, std::string> MySQLBackupStrategy::execute(const std::string& outputPath) {
    if (user.empty() || (password && password->empty())) {
        return std::unexpected("Invalid MySQL credentials: user or password missing");
    }

    fs::path outputFilePath(outputPath);
    fs::create_directories(outputFilePath.parent_path());

#ifdef _WIN32
    std::string mysqldump = "mysqldump.exe";
#else
    std::string mysqldump = "mysqldump";
#endif

    std::string tempSql = std::format("{}.sql", outputPath);
    std::string command = password && !password->empty()
        ? std::format("{} -u {} -p{} --all-databases > {}", mysqldump, user, *password, tempSql)
        : std::format("{} -u {} --all-databases > {}", mysqldump, user, tempSql);
    std::cout << "Backing up all MySQL databases..." << std::endl;
    std::cout << "Executing mysqldump..." << std::flush;
    if (std::system(command.c_str()) != 0) {
        return std::unexpected("Failed to execute mysqldump");
    }

    std::string dbBackupFileGz = std::format("{}.sql.gz", outputPath);
    std::cout << "\nCompressing database backup..." << std::endl;
    std::ifstream inFile(tempSql, std::ios::binary);
    gzFile outFile = gzopen(dbBackupFileGz.c_str(), "wb");
    if (!outFile) {
        fs::remove(tempSql);
        return std::unexpected("Failed to open gzip file for writing");
    }

    char buf[8192];
    while (inFile) {
        inFile.read(buf, sizeof(buf));
        gzwrite(outFile, buf, inFile.gcount());
    }

    gzclose(outFile);
    inFile.close();
    fs::remove(tempSql);
    std::cout << "MySQL backup completed: " << dbBackupFileGz << std::endl;
    return dbBackupFileGz;
}

PostgreSQLBackupStrategy::PostgreSQLBackupStrategy(const std::string& user, std::optional<std::string> password, const std::string& host, int port)
    : user(user), password(password), host(host), port(port) {}

std::expected<std::string, std::string> PostgreSQLBackupStrategy::execute(const std::string& outputPath) {
    if (user.empty() || (password && password->empty()) || host.empty() || port <= 0) {
        return std::unexpected("Invalid PostgreSQL credentials: user, password, host, or port missing");
    }

    fs::path outputFilePath(outputPath);
    fs::create_directories(outputFilePath.parent_path());

#ifdef _WIN32
    std::string pgdumpall = "pg_dumpall.exe";
#else
    std::string pgdumpall = "pg_dumpall";
#endif

    std::string tempSql = std::format("{}.sql", outputPath);
    std::string command = password && !password->empty()
        ? std::format("PGPASSWORD={} {} -U {} -h {} -p {} > {}", *password, pgdumpall, user, host, port, tempSql)
        : std::format("{} -U {} -h {} -p {} > {}", pgdumpall, user, host, port, tempSql);
    std::cout << "Backing up all PostgreSQL databases..." << std::endl;
    std::cout << "Executing pg_dumpall..." << std::flush;
    if (std::system(command.c_str()) != 0) {
        return std::unexpected("Failed to execute pg_dumpall");
    }

    std::string dbBackupFileGz = std::format("{}.sql.gz", outputPath);
    std::cout << "\nCompressing database backup..." << std::endl;
    std::ifstream inFile(tempSql, std::ios::binary);
    gzFile outFile = gzopen(dbBackupFileGz.c_str(), "wb");
    if (!outFile) {
        fs::remove(tempSql);
        return std::unexpected("Failed to open gzip file for writing");
    }

    char buf[8192];
    while (inFile) {
        inFile.read(buf, sizeof(buf));
        gzwrite(outFile, buf, inFile.gcount());
    }

    gzclose(outFile);
    inFile.close();
    fs::remove(tempSql);
    std::cout << "PostgreSQL backup completed: " << dbBackupFileGz << std::endl;
    return dbBackupFileGz;
}