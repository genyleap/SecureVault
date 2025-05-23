/**
 * @file database_backup.hpp
 * @brief Defines database backup strategies for SecureVault.
 *
 * Provides interfaces and implementations for backing up databases, with a focus on MySQL.
 * Designed for cross-platform use, with support for platform-specific database tools.
 *
 * @note Requires database client tools (e.g., mysqldump) in the system PATH.
 * On Windows, install MySQL client; on macOS, use Homebrew; on Linux, use apt.
 */

#ifndef DATABASE_BACKUP_HPP
#define DATABASE_BACKUP_HPP

#include <string>
#include <expected>
#include <optional>

/**
 * @brief Interface for database backup strategies.
 *
 * Defines the contract for backing up databases, supporting multiple database types.
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
     */
    std::expected<std::string, std::string> execute(const std::string& outputPath) override;

private:
    std::string user; ///< MySQL username.
    std::optional<std::string> password; ///< Optional MySQL password.
};

#endif // DATABASE_BACKUP_HPP