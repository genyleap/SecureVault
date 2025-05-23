#include "backup_config.hpp"
#include <fstream>
#include <chrono>
#include <format>
#include <print>
#ifndef _WIN32
#include <pwd.h>
#endif

BackupConfig::BackupConfig(const std::string& configFile) {
    std::ifstream file(configFile);
    if (!file.is_open()) {
        throw std::runtime_error(std::format("Failed to open config file: {}", configFile));
    }
    Json::Value configJson;
    Json::Reader reader;
    if (!reader.parse(file, configJson)) {
        throw std::runtime_error(std::format("Failed to parse config file: {}", configFile));
    }

    backupBase = configJson.get("backup_base", "./backups/").asString();
    sysBackupFolder = backupBase + "sys/";
    dbBackupFolder = backupBase + "db/";
    for (const auto& dir : configJson["backup_dirs"]) {
        backupDirs.push_back(dir.asString());
    }
    if (backupDirs.empty()) {
        backupDirs = getDefaultBackupDirs();
    }
    for (const auto& ext : configJson["exclude_extensions"]) {
        excludeExtensions.push_back(ext.asString());
    }
    retentionDays = configJson.get("retention_days", 7).asInt();
    logFile = backupBase + "backup.log";
    errorLogFile = backupBase + "errors.log";
    lastBackupFile = backupBase + "last_backup.txt";

    // Parse databases section
    if (configJson.isMember("databases")) {
        for (const auto& db : configJson["databases"]) {
            DatabaseConfig dbConfig;
            dbConfig.type = db.get("type", "").asString();
            dbConfig.user = db.get("user", "root").asString();
            dbConfig.password = db.get("password", "").asString();
            dbConfig.host = db.get("host", "localhost").asString();
            dbConfig.port = db.get("port", 0).asInt();
            databases.push_back(dbConfig);
        }
    } else {
        // Fallback to legacy MySQL config
        DatabaseConfig dbConfig;
        dbConfig.type = "mysql";
        dbConfig.user = configJson.get("mysql_user", "root").asString();
        dbConfig.password = configJson.get("mysql_password", "").asString();
        dbConfig.host = "localhost";
        dbConfig.port = 3306;
        databases.push_back(dbConfig);
    }

    sftpConfig = configJson["sftp"];
    telegramConfig = configJson["telegram"];
    emailConfig = configJson["email"];

    Json::Value schedule = configJson["schedule"];
    scheduleType = schedule.get("type", "daily").asString();
    scheduleTime = schedule.get("time", "15:25:00").asString();
    scheduleDayOfWeek = schedule.get("day_of_week", "monday").asString();
    scheduleDayOfMonth = schedule.get("day_of_month", 1).asInt();

#ifdef _WIN32
    username = "Administrator"; // Default for Windows
#else
    struct passwd* pwd = getpwnam("root");
    if (!pwd) {
        throw std::runtime_error("Failed to get current user");
    }
    username = pwd->pw_name;
#endif
}

void BackupConfig::logMessage(const std::string& message) const {
    std::ofstream log(logFile, std::ios::app);
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    char timeBuf[32];
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&timeT));
    std::string logEntry = std::format("[{}] {}", timeBuf, message);

    std::println("{}", logEntry);

    if (log.is_open()) {
        log << logEntry << '\n';
        log.flush();
    } else {
        std::println(stderr, "Error: Cannot write to log file: {}", logFile);
    }
}

void BackupConfig::logError(const std::string& message) const {
    std::ofstream log(errorLogFile, std::ios::app);
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    char timeBuf[32];
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&timeT));
    std::string logEntry = std::format("[{}] ERROR: {}", timeBuf, message);

    std::println(stderr, "{}", logEntry);

    if (log.is_open()) {
        log << logEntry << '\n';
        log.flush();
    } else {
        std::println(stderr, "Error: Cannot write to error log file: {}", errorLogFile);
    }
}

std::vector<std::string> BackupConfig::getDefaultBackupDirs() const {
#ifdef _WIN32
    return {
        "C:/inetpub/wwwroot/",
        "C:/Program Files/Apache Group/Apache2/conf/",
        "C:/Program Files/Apache Group/Apache2/logs/",
        "C:/nginx/conf/",
        "C:/nginx/logs/",
        "C:/Program Files/PostgreSQL/data/",
        "C:/Program Files/PostgreSQL/logs/",
        "C:/Users/Administrator/",
        "C:/Windows/System32/config/systemprofile/"
    };
#elif __APPLE__
    return {
        "/Library/WebServer/Documents/",
        "/etc/apache2/",
        "/var/log/apache2/",
        "/usr/local/etc/nginx/",
        "/usr/local/var/log/nginx/",
        "/Library/PostgreSQL/data/",
        "/Library/PostgreSQL/logs/",
        "/Users/root/",
        "/etc/launchd/"
    };
#else
    return {
        "/var/www/",
        "/etc/apache2/",
        "/var/log/apache2/",
        "/etc/nginx/",
        "/var/log/nginx/",
        "/etc/postgresql/",
        "/var/log/postgresql/",
        "/home/root/",
        "/etc/systemd/system/"
    };
#endif
}