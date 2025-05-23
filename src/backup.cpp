#include "backup.hpp"
#include "backup_api.hpp"
#include <archive.h>
#include <archive_entry.h>
#include <iostream>
#include <thread>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <csignal>
#include <cerrno>
#include <filesystem>
#ifndef _WIN32
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

namespace fs = std::filesystem;

volatile std::sig_atomic_t gShutdownFlag = 0;

void signalHandler(int /*sig*/) {
    gShutdownFlag = 1;
}

void changeOwnership(const std::string& path, const std::string& user, const std::string& groupName) {
#ifndef _WIN32
    struct passwd* pwd = getpwnam(user.c_str());
    struct group* grp = getgrnam(groupName.c_str());
    if (!pwd || !grp) {
        throw std::runtime_error("Invalid user or group");
    }
    if (chown(path.c_str(), pwd->pw_uid, grp->gr_gid) != 0) {
        throw std::runtime_error(std::format("Failed to change ownership: {} (error: {})", path, strerror(errno)));
    }
#else
    // Optional: Implement Windows SetFileSecurity if needed
#endif
}

Backup::Backup(const std::string& configFile) : config(configFile) {
    if (!config.databases.empty()) {
        const auto& db = config.databases[0];
        if (db.type == "mysql") {
            dbStrategy = std::make_unique<MySQLBackupStrategy>(db.user, db.password);
        } else if (db.type == "postgresql") {
            dbStrategy = std::make_unique<PostgreSQLBackupStrategy>(db.user, db.password, db.host, db.port);
        } else {
            throw std::runtime_error(std::format("Unsupported database type: {}", db.type));
        }
    } else {
        throw std::runtime_error("No database configuration provided");
    }

    fileStrategy = std::make_unique<TarGzFileBackupStrategy>(config.excludeExtensions, config.lastBackupFile);
    if (!config.sftpConfig.empty()) {
        transferStrategy = std::make_unique<SFTPTransferStrategy>(config.sftpConfig);
    }
    if (!config.telegramConfig.empty()) {
        notificationStrategy = std::make_unique<TelegramNotificationStrategy>(config.telegramConfig);
    } else if (!config.emailConfig.empty()) {
        notificationStrategy = std::make_unique<EmailNotificationStrategy>(config.emailConfig);
    }
}

std::expected<void, std::string> Backup::execute(const std::string& type, bool fullBackup) {
    std::string dateFormat;
    if (type == "daily") {
        dateFormat = "%d";
    } else if (type == "monthly") {
        dateFormat = "%m";
    } else if (type == "yearly") {
        dateFormat = "%Y";
    } else {
        config.logError(std::format("Invalid backup type: {}", type));
        return std::unexpected("Invalid backup type. Use daily, monthly, or yearly.");
    }

    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    char dateBuf[32];
    std::strftime(dateBuf, sizeof(dateBuf), dateFormat.c_str(), std::localtime(&timeT));
    char timestampBuf[32];
    std::strftime(timestampBuf, sizeof(timestampBuf), "%Y%m%d-%H%M%S", std::localtime(&timeT));
    std::string targetFilename = std::format("sys-{}-{}-{}.tar.gz", type, dateBuf, timestampBuf);
    std::string targetPath = config.sysBackupFolder + targetFilename;

    std::string dbBaseFilename = std::format("all_databases_{}", timestampBuf);
    std::string dbTargetPath = config.dbBackupFolder + dbBaseFilename;
    std::string dbBackupFile;
    auto dbResult = dbStrategy->execute(dbTargetPath);
    if (!dbResult) {
        auto errorMsg = std::format("Database backup failed: {}", dbResult.error());
        config.logError(errorMsg);
        if (notificationStrategy) {
            notificationStrategy->notify(errorMsg);
        }
        std::cerr << "Warning: " << errorMsg << ", proceeding with file backup." << std::endl;
    } else {
        dbBackupFile = *dbResult;
    }

    auto fileResult = fileStrategy->execute(config.backupDirs, targetPath, fullBackup);
    if (!fileResult) {
        auto errorMsg = std::format("File backup failed: {}", fileResult.error());
        config.logError(errorMsg);
        if (notificationStrategy) {
            notificationStrategy->notify(errorMsg);
        }
        return std::unexpected(errorMsg);
    }

    auto verifyResult = verifyBackup(targetPath);
    if (!verifyResult || !*verifyResult) {
        auto errorMsg = std::format("Backup verification failed: {}", verifyResult.error());
        config.logError(errorMsg);
        if (notificationStrategy) {
            notificationStrategy->notify(errorMsg);
        }
        return std::unexpected(errorMsg);
    }

    try {
        changeOwnership(targetPath, config.username, config.username);
        if (!dbBackupFile.empty()) {
            changeOwnership(dbBackupFile, config.username, config.username);
        }
    } catch (const std::exception& e) {
        auto errorMsg = std::format("Failed to change ownership: {}", e.what());
        config.logError(errorMsg);
        if (notificationStrategy) {
            notificationStrategy->notify(errorMsg);
        }
        return std::unexpected(errorMsg);
    }

    if (transferStrategy) {
        auto transferResult = transferStrategy->transfer(targetPath, config.sysBackupFolder);
        if (!transferResult) {
            auto errorMsg = std::format("File transfer failed: {}", transferResult.error());
            config.logError(errorMsg);
            if (notificationStrategy) {
                notificationStrategy->notify(errorMsg);
            }
        }
        if (!dbBackupFile.empty()) {
            transferResult = transferStrategy->transfer(dbBackupFile, config.dbBackupFolder);
            if (!transferResult) {
                auto errorMsg = std::format("Database transfer failed: {}", transferResult.error());
                config.logError(errorMsg);
                if (notificationStrategy) {
                    notificationStrategy->notify(errorMsg);
                }
            }
        }
    }

    auto cleanupResult = cleanupOldBackups();
    if (!cleanupResult) {
        auto errorMsg = std::format("Cleanup failed: {}", cleanupResult.error());
        config.logError(errorMsg);
        if (notificationStrategy) {
            notificationStrategy->notify(errorMsg);
        }
    }

    auto successMsg = std::format("Backup completed: {} and {}", targetPath, dbBackupFile.empty() ? "no database backup" : dbBackupFile);
    config.logMessage(successMsg);
    if (notificationStrategy) {
        notificationStrategy->notify(successMsg);
    }

    return {};
}

std::expected<void, std::string> Backup::cleanupOldBackups() {
    auto now = std::chrono::system_clock::now();
    auto threshold = now - std::chrono::hours(24 * config.retentionDays);

    for (const auto& folder : {config.sysBackupFolder, config.dbBackupFolder}) {
        for (const auto& entry : fs::directory_iterator(folder)) {
            if (entry.is_regular_file()) {
                auto lastWrite = fs::last_write_time(entry);
                auto fileTime = std::chrono::system_clock::now() - (std::chrono::system_clock::now() - std::chrono::file_clock::to_sys(lastWrite));
                if (fileTime < threshold) {
                    try {
                        fs::remove(entry);
                        config.logMessage(std::format("Removed old backup: {}", entry.path().string()));
                    } catch (const std::exception& e) {
                        config.logError(std::format("Failed to remove old backup: {} (error: {})", entry.path().string(), e.what()));
                        return std::unexpected(std::format("Failed to remove old backup: {}", e.what()));
                    }
                }
            }
        }
    }
    return {};
}

std::expected<bool, std::string> Backup::verifyBackup(const std::string& backupFile) {
    struct archive* a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_tar(a);
    if (archive_read_open_filename(a, backupFile.c_str(), 10240) != ARCHIVE_OK) {
        std::string errorMsg = std::format("Failed to open archive for verification: {} (error: {})", backupFile, archive_error_string(a));
        config.logError(errorMsg);
        archive_read_free(a);
        return std::unexpected(errorMsg);
    }

    struct archive_entry* entry;
    bool success = true;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        archive_read_data_skip(a);
    }

    archive_read_close(a);
    archive_read_free(a);
    return success;
}

std::chrono::system_clock::time_point Backup::getNextBackupTime() const {
    auto now = std::chrono::system_clock::now();
    auto nowT = std::chrono::system_clock::to_time_t(now);
    std::tm tmNow = *std::localtime(&nowT);

    int hour, minute, second;
    std::istringstream ss(config.scheduleTime);
    char colon;
    ss >> hour >> colon >> minute >> colon >> second;
    if (ss.fail() || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
        config.logError(std::format("Invalid schedule time format: {}", config.scheduleTime));
        throw std::runtime_error(std::format("Invalid schedule time format: {}", config.scheduleTime));
    }

    std::tm tmNext = tmNow;
    tmNext.tm_hour = hour;
    tmNext.tm_min = minute;
    tmNext.tm_sec = second;
    tmNext.tm_isdst = -1;

    auto nextTime = std::chrono::system_clock::from_time_t(std::mktime(&tmNext));
    config.logMessage(std::format("Debug: Initial next backup time: {}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}",
                                  tmNext.tm_year + 1900, tmNext.tm_mon + 1, tmNext.tm_mday, tmNext.tm_hour, tmNext.tm_min, tmNext.tm_sec));

    if (config.scheduleType == "daily") {
        if (nextTime <= now) {
            tmNext.tm_mday += 1;
            nextTime = std::chrono::system_clock::from_time_t(std::mktime(&tmNext));
            config.logMessage(std::format("Debug: Adjusted to next day: {}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}",
                                          tmNext.tm_year + 1900, tmNext.tm_mon + 1, tmNext.tm_mday, tmNext.tm_hour, tmNext.tm_min, tmNext.tm_sec));
        }
    } else if (config.scheduleType == "weekly") {
        std::map<std::string, int> dayMap = {
            {"monday", 1}, {"tuesday", 2}, {"wednesday", 3}, {"thursday", 4},
            {"friday", 5}, {"saturday", 6}, {"sunday", 0}
        };
        auto it = dayMap.find(config.scheduleDayOfWeek);
        if (it == dayMap.end()) {
            config.logError(std::format("Invalid day of week: {}", config.scheduleDayOfWeek));
            throw std::runtime_error(std::format("Invalid day of week: {}", config.scheduleDayOfWeek));
        }
        int targetDay = it->second;
        int currentDay = tmNow.tm_wday;
        int daysToAdd = (targetDay - currentDay + 7) % 7;
        if (daysToAdd == 0 && nextTime <= now) {
            daysToAdd = 7;
        }
        tmNext.tm_mday += daysToAdd;
        nextTime = std::chrono::system_clock::from_time_t(std::mktime(&tmNext));
        config.logMessage(std::format("Debug: Adjusted to next week: {}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}",
                                      tmNext.tm_year + 1900, tmNext.tm_mon + 1, tmNext.tm_mday, tmNext.tm_hour, tmNext.tm_min, tmNext.tm_sec));
    } else if (config.scheduleType == "monthly") {
        int targetDay = config.scheduleDayOfMonth;
        if (targetDay < 1 || targetDay > 31) {
            config.logError(std::format("Invalid day of month: {}", targetDay));
            throw std::runtime_error(std::format("Invalid day of month: {}", targetDay));
        }
        tmNext.tm_mday = targetDay;
        if (tmNext.tm_mday <= tmNow.tm_mday && nextTime <= now) {
            tmNext.tm_mon += 1;
            if (tmNext.tm_mon > 11) {
                tmNext.tm_mon = 0;
                tmNext.tm_year += 1;
            }
            tmNext.tm_mday = targetDay;
            nextTime = std::chrono::system_clock::from_time_t(std::mktime(&tmNext));
            config.logMessage(std::format("Debug: Adjusted to next month: {}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}",
                                          tmNext.tm_year + 1900, tmNext.tm_mon + 1, tmNext.tm_mday, tmNext.tm_hour, tmNext.tm_min, tmNext.tm_sec));
        }
    } else {
        config.logError(std::format("Invalid schedule type: {}", config.scheduleType));
        throw std::runtime_error(std::format("Invalid schedule type: {}", config.scheduleType));
    }

    return nextTime;
}

void Backup::runDaemon() {
    fs::path logPath(config.logFile);
    fs::create_directories(logPath.parent_path());

    std::ofstream logTest(config.logFile, std::ios::app);
    if (!logTest.is_open()) {
        std::cerr << "Error: Cannot open log file: " << config.logFile << std::endl;
        return;
    }
    logTest.close();

#ifdef _WIN32
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
#else
    struct sigaction sa;
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
#endif

    std::cout << "Daemon mode started. Check " << config.logFile << " for logs." << std::endl;

    while (!gShutdownFlag) {
        try {
            auto nextBackup = getNextBackupTime();
            auto now = std::chrono::system_clock::now();
            auto sleepDuration = std::chrono::duration_cast<std::chrono::seconds>(nextBackup - now);

            std::stringstream ss;
            auto nextT = std::chrono::system_clock::to_time_t(nextBackup);
            ss << std::put_time(std::localtime(&nextT), "%Y-%m-%d %H:%M:%S");

            auto nowT = std::chrono::system_clock::to_time_t(now);
            std::stringstream ssNow;
            ssNow << std::put_time(std::localtime(&nowT), "%Y-%m-%d %H:%M:%S");

            config.logMessage(std::format("Debug: Current time: {}", ssNow.str()));
            config.logMessage(std::format("Debug: Calculated next backup at {}", ss.str()));
            config.logMessage(std::format("Debug: Sleep duration: {} seconds", sleepDuration.count()));

            if (sleepDuration.count() > 0 && !gShutdownFlag) {
                config.logMessage(std::format("Next backup scheduled at {}", ss.str()));
                auto remaining = sleepDuration.count();
                while (remaining > 0 && !gShutdownFlag) {
                    auto sleepFor = std::min(remaining, static_cast<std::chrono::seconds::rep>(1));
                    std::this_thread::sleep_for(std::chrono::seconds(sleepFor));
                    remaining -= sleepFor;
                }
            } else if (!gShutdownFlag) {
                config.logMessage("Debug: Sleep duration is zero or negative, proceeding to backup immediately");
                auto result = execute(config.scheduleType);
                if (!result) {
                    config.logError(std::format("Backup failed: {}", result.error()));
                    if (notificationStrategy) {
                        notificationStrategy->notify(result.error());
                    }
                } else {
                    config.logMessage("Backup completed successfully");
                }
            } else {
                break;
            }
        } catch (const std::exception& e) {
            config.logError(std::format("Daemon error: {}", e.what()));
            std::cerr << "Daemon error: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(60));
            if (gShutdownFlag) {
                break;
            }
        }
    }
    config.logMessage("Daemon shutting down gracefully");
}

int main(int argc, char* argv[]) {
    bool daemonMode = false;
    bool fullBackup = false;
    std::string backupType;
    std::string configFile = "backup_config.json";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--daemon") {
            daemonMode = true;
        } else if (arg == "--full") {
            fullBackup = true;
        } else if (arg == "--config" && i + 1 < argc) {
            configFile = argv[++i];
        } else {
            backupType = arg;
        }
    }

    if (daemonMode && backupType.empty()) {
        try {
            BackupConfig config(configFile);
            backupType = config.scheduleType;
        } catch (const std::exception& e) {
            std::cerr << "Error: Failed to load config: " << e.what() << std::endl;
            return 1;
        }
    }

    if (backupType.empty()) {
        std::cerr << "Usage: " << argv[0] << " [--daemon] [--full] [--config <path>] {daily|monthly|yearly}" << std::endl;
        return 1;
    }

    if (!daemonMode) {
        auto result = BackupAPI::startBackup(backupType, fullBackup);
        if (!result) {
            std::cerr << "Error: " << result.error() << std::endl;
            return 1;
        }
    }

    if (daemonMode) {
        std::cout << "Entering daemon mode, waiting for scheduled backup at " << configFile << std::endl;
        try {
            Backup backup(configFile);
            backup.runDaemon();
        } catch (const std::exception& e) {
            std::cerr << "Error: Daemon failed to start: " << e.what() << std::endl;
            return 1;
        }
    } else {
        std::cout << "Backup completed successfully." << std::endl;
    }

    return 0;
}
