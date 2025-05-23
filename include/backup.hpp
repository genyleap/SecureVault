/**
 * @file backup.hpp
 * @brief Defines the core backup system classes for SecureVault.
 *
 * This header provides the main interfaces and implementations for database and file backups,
 * remote transfers, notifications, and the backup orchestration logic. The system is designed
 * to be cross-platform, supporting Windows, macOS, and Linux, with platform-specific considerations
 * for filesystem operations, signal handling, and ownership management.
 *
 * @note Ensure platform-specific dependencies (e.g., libarchive, libssh, libcurl) are installed.
 * On Windows, use vcpkg or MSYS2; on macOS, use Homebrew; on Linux, use apt or equivalent.
 */

#ifndef BACKUP_HPP
#define BACKUP_HPP

#include <string>
#include <vector>
#include <memory>
#include <expected>
#include <filesystem>
#include <chrono>
#include "backup_config.hpp"

namespace fs = std::filesystem;

/**
 * @brief Abstract base class for database backup strategies.
 *
 * Defines the interface for backing up databases, used by concrete strategies like MySQL and PostgreSQL.
 * Implementations must handle platform-specific database tools (e.g., mysqldump, pg_dumpall).
 */
class DatabaseBackupStrategy {
public:
    /**
     * @brief Virtual destructor for safe polymorphism.
     */
    virtual ~DatabaseBackupStrategy() = default;

    /**
     * @brief Executes a database backup.
     *
     * Creates a compressed backup file at the specified path.
     *
     * @param outputPath Base path for the output file (without .sql.gz extension).
     * @return std::expected<std::string, std::string> Path to the backup file or an error message.
     * @note Ensure database tools (e.g., mysqldump, pg_dumpall) are in the system PATH.
     */
    virtual std::expected<std::string, std::string> execute(const std::string& outputPath) = 0;
};

/**
 * @brief MySQL database backup strategy using mysqldump.
 *
 * Implements backup for MySQL databases, producing a compressed .sql.gz file.
 */
class MySQLBackupStrategy : public DatabaseBackupStrategy {
public:
    /**
     * @brief Constructs a MySQL backup strategy.
     *
     * @param user MySQL username.
     * @param password Optional MySQL password. If empty, uses system credentials (e.g., ~/.my.cnf).
     */
    MySQLBackupStrategy(const std::string& user, std::optional<std::string> password);

    /**
     * @brief Executes a MySQL backup.
     *
     * Runs mysqldump to back up all databases and compresses the output.
     *
     * @param outputPath Base path for the output file (without .sql.gz extension).
     * @return std::expected<std::string, std::string> Path to the backup file or an error message.
     * @note Requires mysqldump in the system PATH. On Windows, ensure MySQL client is installed.
     */
    std::expected<std::string, std::string> execute(const std::string& outputPath) override;

private:
    std::string user; ///< MySQL username.
    std::optional<std::string> password; ///< Optional MySQL password.
};

/**
 * @brief PostgreSQL database backup strategy using pg_dumpall.
 *
 * Implements backup for PostgreSQL databases, producing a compressed .sql.gz file.
 */
class PostgreSQLBackupStrategy : public DatabaseBackupStrategy {
public:
    /**
     * @brief Constructs a PostgreSQL backup strategy.
     *
     * @param user PostgreSQL username.
     * @param password Optional PostgreSQL password.
     * @param host Database host (e.g., "localhost").
     * @param port Database port (e.g., 5432).
     */
    PostgreSQLBackupStrategy(const std::string& user, std::optional<std::string> password, const std::string& host, int port);

    /**
     * @brief Executes a PostgreSQL backup.
     *
     * Runs pg_dumpall to back up all databases and compresses the output.
     *
     * @param outputPath Base path for the output file (without .sql.gz extension).
     * @return std::expected<std::string, std::string> Path to the backup file or an error message.
     * @note Requires pg_dumpall in the system PATH. On Windows, ensure PostgreSQL client is installed.
     */
    std::expected<std::string, std::string> execute(const std::string& outputPath) override;

private:
    std::string user; ///< PostgreSQL username.
    std::optional<std::string> password; ///< Optional PostgreSQL password.
    std::string host; ///< Database host.
    int port; ///< Database port.
};

/**
 * @brief Abstract base class for file backup strategies.
 *
 * Defines the interface for backing up files and directories.
 */
class FileBackupStrategy {
public:
    /**
     * @brief Virtual destructor for safe polymorphism.
     */
    virtual ~FileBackupStrategy() = default;

    /**
     * @brief Executes a file backup.
     *
     * Backs up specified directories to a single output file.
     *
     * @param sourceDirs List of directories to back up.
     * @param outputFile Path for the output backup file.
     * @param fullBackup If true, performs a full backup; otherwise, incremental.
     * @return std::expected<void, std::string> Success or an error message.
     * @note Uses std::filesystem for portable path handling across Windows, macOS, and Linux.
     */
    virtual std::expected<void, std::string> execute(const std::vector<std::string>& sourceDirs,
                                                    const std::string& outputFile,
                                                    bool fullBackup) = 0;
};

/**
 * @brief Tar.gz file backup strategy with incremental and threaded support.
 *
 * Implements file backup using tar.gz format, with multi-threaded processing and incremental backups.
 */
class TarGzFileBackupStrategy : public FileBackupStrategy {
public:
    /**
     * @brief Constructs a tar.gz backup strategy.
     *
     * @param excludeExtensions File extensions to exclude (e.g., {".tmp", ".bak"}).
     * @param lastBackupFile Path to file storing the last backup timestamp.
     */
    TarGzFileBackupStrategy(const std::vector<std::string>& excludeExtensions, const std::string& lastBackupFile);

    /**
     * @brief Executes a tar.gz file backup.
     *
     * Creates a compressed tar.gz backup of specified directories, supporting incremental backups
     * and excluding specified file extensions.
     *
     * @param sourceDirs List of directories to back up.
     * @param outputFile Path for the output .tar.gz file.
     * @param fullBackup If true, performs a full backup; otherwise, incremental.
     * @return std::expected<void, std::string> Success or an error message.
     * @note Requires libarchive. On Windows, install via vcpkg; on macOS, use Homebrew.
     */
    std::expected<void, std::string> execute(const std::vector<std::string>& sourceDirs,
                                             const std::string& outputFile,
                                             bool fullBackup) override;

private:
    std::vector<std::string> excludeExtensions; ///< File extensions to exclude.
    std::string lastBackupFile; ///< Path to last backup timestamp file.
};

/**
 * @brief Abstract base class for remote transfer strategies.
 *
 * Defines the interface for transferring backup files to remote locations.
 */
class TransferStrategy {
public:
    /**
     * @brief Virtual destructor for safe polymorphism.
     */
    virtual ~TransferStrategy() = default;

    /**
     * @brief Transfers a file to a remote location.
     *
     * Sends the specified file to the configured remote destination.
     *
     * @param sourceFile Path to the local file.
     * @param destinationPath Remote directory path.
     * @return std::expected<void, std::string> Success or an error message.
     */
    virtual std::expected<void, std::string> transfer(const std::string& sourceFile, const std::string& destinationPath) = 0;
};

/**
 * @brief SFTP remote transfer strategy.
 *
 * Implements file transfers using the SFTP protocol.
 */
class SFTPTransferStrategy : public TransferStrategy {
public:
    /**
     * @brief Constructs an SFTP transfer strategy.
     *
     * @param config JSON configuration with host, user, password, port, and remote_dir.
     */
    SFTPTransferStrategy(const Json::Value& config);

    /**
     * @brief Transfers a file via SFTP.
     *
     * Sends the local file to the specified remote directory.
     *
     * @param sourceFile Path to the local file.
     * @param destinationPath Remote directory path.
     * @return std::expected<void, std::string> Success or an error message.
     * @note Requires libssh. On Windows, install via vcpkg; on macOS, use Homebrew.
     */
    std::expected<void, std::string> transfer(const std::string& sourceFile, const std::string& destinationPath) override;
};

/**
 * @brief Abstract base class for notification strategies.
 *
 * Defines the interface for sending notifications about backup status.
 */
class NotificationStrategy {
public:
    /**
     * @brief Virtual destructor for safe polymorphism.
     */
    virtual ~NotificationStrategy() = default;

    /**
     * @brief Sends a notification.
     *
     * Delivers the specified message via the configured notification channel.
     *
     * @param message Message to send.
     * @return std::expected<void, std::string> Success or an error message.
     */
    virtual std::expected<void, std::string> notify(const std::string& message) = 0;
};

/**
 * @brief Telegram notification strategy.
 *
 * Sends notifications using the Telegram Bot API.
 */
class TelegramNotificationStrategy : public NotificationStrategy {
public:
    /**
     * @brief Constructs a Telegram notification strategy.
     *
     * @param config JSON configuration with bot_token and chat_id.
     */
    TelegramNotificationStrategy(const Json::Value& config);

    /**
     * @brief Sends a notification via Telegram.
     *
     * Sends the message to the configured Telegram chat.
     *
     * @param message Message to send.
     * @return std::expected<void, std::string> Success or an error message.
     * @note Requires libcurl. On Windows, install via vcpkg; on macOS, use Homebrew.
     */
    std::expected<void, std::string> notify(const std::string& message) override;

private:
    std::string botToken; ///< Telegram bot token.
    std::string chatId; ///< Telegram chat ID.
};

/**
 * @brief Email notification strategy.
 *
 * Sends notifications using SMTP email.
 */
class EmailNotificationStrategy : public NotificationStrategy {
public:
    /**
     * @brief Constructs an email notification strategy.
     *
     * @param config JSON configuration with email_to, smtp_server, and optional credentials.
     */
    EmailNotificationStrategy(const Json::Value& config);

    /**
     * @brief Sends a notification via email.
     *
     * Sends the message to the configured email address.
     *
     * @param message Message to send.
     * @return std::expected<void, std::string> Success or an error message.
     * @note Requires libcurl for SMTP. Configure SMTP credentials in backup_config.json.
     */
    std::expected<void, std::string> notify(const std::string& message) override;

private:
    std::string emailTo; ///< Recipient email address.
    std::string smtpServer; ///< SMTP server address.
};

/**
 * @brief Main backup orchestration class.
 *
 * Manages the backup process, coordinating database and file backups, remote transfers,
 * and notifications based on the provided configuration.
 */
class Backup {
public:
    /**
     * @brief Constructs a backup instance.
     *
     * Initializes strategies based on the configuration file.
     *
     * @param configFile Path to the JSON configuration file.
     * @throws std::runtime_error If configuration is invalid or dependencies are missing.
     */
    Backup(const std::string& configFile);

    /**
     * @brief Executes a backup.
     *
     * Performs a backup of the specified type, coordinating database and file backups.
     *
     * @param type Backup type ("daily", "monthly", "yearly").
     * @param fullBackup If true, performs a full backup; otherwise, incremental.
     * @return std::expected<void, std::string> Success or an error message.
     */
    std::expected<void, std::string> execute(const std::string& type, bool fullBackup = false);

    /**
     * @brief Cleans up old backup files.
     *
     * Removes backups older than the retention period specified in the configuration.
     *
     * @return std::expected<void, std::string> Success or an error message.
     */
    std::expected<void, std::string> cleanupOldBackups();

    /**
     * @brief Calculates the next scheduled backup time.
     *
     * Determines the next backup time based on the schedule configuration.
     *
     * @return std::chrono::system_clock::time_point The next backup time.
     */
    std::chrono::system_clock::time_point getNextBackupTime() const;

    /**
     * @brief Runs the backup system in daemon mode.
     *
     * Executes scheduled backups in a loop until interrupted.
     *
     * @note On Windows, signal handling is limited to SIGINT/SIGTERM. Use Ctrl+C to stop.
     */
    void runDaemon();

private:
    /**
     * @brief Verifies the integrity of a backup file.
     *
     * Checks if the backup file is a valid tar.gz archive.
     *
     * @param backupFile Path to the backup file.
     * @return std::expected<bool, std::string> True if valid, or an error message.
     */
    std::expected<bool, std::string> verifyBackup(const std::string& backupFile);

    BackupConfig config; ///< Backup configuration.
    std::unique_ptr<DatabaseBackupStrategy> dbStrategy; ///< Database backup strategy.
    std::unique_ptr<FileBackupStrategy> fileStrategy; ///< File backup strategy.
    std::unique_ptr<TransferStrategy> transferStrategy; ///< Remote transfer strategy.
    std::unique_ptr<NotificationStrategy> notificationStrategy; ///< Notification strategy.
};

#endif // BACKUP_HPP