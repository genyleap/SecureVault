/**
 * @file backup_config.hpp
 * @brief Configuration management for the SecureVault backup system.
 *
 * Defines the configuration structure and class for managing backup settings, including
 * directories, databases, schedules, and notifications. Supports cross-platform paths
 * and extensible database configurations.
 *
 * @note Configuration is loaded from a JSON file. Ensure paths are platform-appropriate
 * (e.g., use forward slashes for Linux/macOS, backslashes or forward slashes for Windows).
 */

#ifndef BACKUP_CONFIG_HPP
#define BACKUP_CONFIG_HPP

#include <string>
#include <vector>
#include <optional>
#include <json/json.h>

/**
 * @brief Structure for database configuration.
 *
 * Holds settings for a single database, supporting multiple types (e.g., MySQL, PostgreSQL).
 */
struct DatabaseConfig {
    std::string type; ///< Database type ("mysql", "postgresql").
    std::string user; ///< Database username.
    std::optional<std::string> password; ///< Optional database password.
    std::string host; ///< Database host (e.g., "localhost").
    int port; ///< Database port (e.g., 3306 for MySQL, 5432 for PostgreSQL).
};

/**
 * @brief Configuration class for the backup system.
 *
 * Loads and manages settings from a JSON configuration file, providing defaults and validation.
 */
class BackupConfig {
public:
    /**
     * @brief Constructs a configuration instance from a JSON file.
     *
     * Loads settings from the specified file, applying defaults where needed.
     *
     * @param configFile Path to the JSON configuration file.
     * @throws std::runtime_error If the file is invalid or inaccessible.
     * @note Use platform-appropriate paths (e.g., "C:\\Backups\\config.json" on Windows).
     */
    BackupConfig(const std::string& configFile);

    /**
     * @brief Logs a message to the configured log file.
     *
     * @param message Message to log.
     * @note Ensures the log file directory exists on all platforms.
     */
    void logMessage(const std::string& message) const;

    /**
     * @brief Logs an error to the configured error log file.
     *
     * @param message Error message to log.
     * @note Ensures the error log file directory exists on all platforms.
     */
    void logError(const std::string& message) const;

    /**
     * @brief Returns the default backup directories.
     *
     * Provides a list of default directories to back up if none are specified in the config.
     *
     * @return std::vector<std::string> List of default directories.
     * @note Directories are platform-specific (e.g., "/var/www/" on Linux, "C:\\inetpub\\" on Windows).
     */
    std::vector<std::string> getDefaultBackupDirs() const;

    std::string backupBase;                         ///< Base directory for backups (e.g., "/var/backups/securevault/").
    std::string sysBackupFolder;                    ///< Directory for system backups.
    std::string dbBackupFolder;                     ///< Directory for database backups.
    std::vector<std::string> backupDirs;            ///< Directories to back up.
    std::vector<std::string> excludeExtensions;     ///< File extensions to exclude.
    int retentionDays;                              ///< Number of days to retain backups.
    std::string logFile;                            ///< Path to the log file.
    std::string errorLogFile;                       ///< Path to the error log file.
    std::string lastBackupFile;                     ///< Path to the last backup timestamp file.
    std::vector<DatabaseConfig> databases;          ///< List of database configurations.
    Json::Value sftpConfig;                         ///< SFTP configuration for remote transfers.
    Json::Value telegramConfig;                     ///< Telegram configuration for notifications.
    Json::Value emailConfig;                        ///< Email configuration for notifications.
    std::string scheduleType;                       ///< Schedule type ("daily", "weekly", "monthly").
    std::string scheduleTime;                       ///< Schedule time (e.g., "15:25:00").
    std::string scheduleDayOfWeek;                  ///< Day of week for weekly schedules.
    int scheduleDayOfMonth;                         ///< Day of month for monthly schedules.
    std::string username;                           ///< User for file ownership (Linux/macOS only).

    std::string mysqlUser;                          ///< Legacy MySQL username.
    std::optional<std::string> mysqlPassword;       ///< Legacy MySQL password.
};

#endif // BACKUP_CONFIG_HPP
