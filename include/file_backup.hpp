/**
 * @file file_backup.hpp
 * @brief Defines file backup strategies for SecureVault.
 *
 * Provides interfaces and implementations for backing up files and directories,
 * with support for tar.gz compression, incremental backups, and multi-threaded processing.
 * Designed for cross-platform use, leveraging std::filesystem for portability.
 *
 * @note Requires libarchive for tar.gz compression. Install via vcpkg on Windows,
 * Homebrew on macOS, or apt on Linux.
 */

#ifndef FILE_BACKUP_HPP
#define FILE_BACKUP_HPP

#include <vector>
#include <string>
#include <expected>
#include <atomic>
#include <mutex>

/**
 * @brief Interface for file backup strategies.
 *
 * Defines the contract for backing up files and directories.
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
     * Backs up the specified directories to a single output file.
     *
     * @param sourceDirs List of directories to back up.
     * @param outputFile Path for the output backup file.
     * @param fullBackup If true, performs a full backup; otherwise, incremental.
     * @return std::expected<void, std::string> Success or an error message.
     */
    virtual std::expected<void, std::string> execute(const std::vector<std::string>& sourceDirs,
                                                    const std::string& outputFile,
                                                    bool fullBackup = false) = 0;
};

/**
 * @brief Tar.gz file backup strategy with incremental and threaded support.
 *
 * Implements file backup using tar.gz format, with multi-threaded processing,
 * incremental backups, and file extension filtering.
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
     * Creates a compressed tar.gz backup of the specified directories, with progress
     * reporting and multi-threaded processing.
     *
     * @param sourceDirs List of directories to back up.
     * @param outputFile Path for the output .tar.gz file.
     * @param fullBackup If true, performs a full backup; otherwise, incremental.
     * @return std::expected<void, std::string> Success or an error message.
     * @note Supports interrupt handling (Ctrl+C) via gShutdownFlag on all platforms.
     */
    std::expected<void, std::string> execute(const std::vector<std::string>& sourceDirs,
                                             const std::string& outputFile,
                                             bool fullBackup = false) override;

private:
    std::vector<std::string> excludeExtensions; ///< File extensions to exclude.
    std::string lastBackupFile; ///< Path to last backup timestamp file.

    /**
     * @brief Counts files to back up.
     *
     * Determines the number of files to process, considering incremental backups and exclusions.
     *
     * @param sourceDirs List of directories to scan.
     * @param fullBackup If true, ignores last backup time.
     * @return size_t Number of files to back up.
     */
    size_t countFiles(const std::vector<std::string>& sourceDirs, bool fullBackup);

    /**
     * @brief Backs up a single directory in a thread.
     *
     * Processes files in the specified directory, adding them to the shared archive.
     *
     * @param dir Directory to back up.
     * @param outputFile Path for the output .tar.gz file.
     * @param fullBackup If true, performs a full backup.
     * @param archive Shared archive object.
     * @param processedFiles Counter for processed files.
     * @param totalFiles Total number of files for progress.
     * @param mutex Mutex for thread-safe archive access.
     */
    void backupDirectory(const std::string& dir,
                         [[maybe_unused]]const std::string& outputFile,
                         bool fullBackup,
                         struct archive* archive,
                         [[maybe_unused]]std::atomic<size_t>& processedFiles,
                         size_t totalFiles,
                         std::mutex& mutex);
};

#endif // FILE_BACKUP_HPP