/**
 * @file backup_api.hpp
 * @brief High-level API for interacting with the SecureVault backup system.
 *
 * Provides a simplified interface for starting backups and updating schedules,
 * abstracting the underlying backup orchestration. Cross-platform compatible,
 * with configuration managed via JSON files.
 *
 * @note Ensure backup_config.json uses platform-appropriate paths and dependencies
 * (e.g., libarchive, libssh) are installed.
 */

#ifndef BACKUP_API_HPP
#define BACKUP_API_HPP

#include <string>
#include <expected>
#include <json/json.h>

/**
 * @brief API for managing backups in SecureVault.
 *
 * Offers methods to initiate backups and update schedules, serving as the primary
 * entry point for external applications.
 */
class BackupAPI {
public:
    /**
     * @brief Starts a backup process.
     *
     * Initiates a backup of the specified type, using the configuration from backup_config.json.
     *
     * @param type Backup type ("daily", "monthly", "yearly").
     * @param fullBackup If true, performs a full backup; otherwise, incremental.
     * @return std::expected<void, std::string> Success or an error message.
     */
    static std::expected<void, std::string> startBackup(const std::string& type, bool fullBackup = false);

    /**
     * @brief Updates the backup schedule.
     *
     * Modifies the schedule configuration in the JSON file.
     *
     * @param schedule JSON object with new schedule settings (type, time, day_of_week, day_of_month).
     * @return std::expected<void, std::string> Success or an error message.
     * @note The JSON file path is defined in the configuration (e.g., backup_config.json).
     */
    static std::expected<void, std::string> updateSchedule(const Json::Value& schedule);
};

#endif // BACKUP_API_HPP
