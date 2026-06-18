/**
 * @file file_backup.cpp
 * @brief File backup strategy implementation for SecureVault.
 *
 * Implements tar.gz backups with threading, incremental support, and signal handling.
 * Cross-platform with std::filesystem and libarchive.
 */

#include "file_backup.hpp"
#include <filesystem>
#include <archive.h>
#include <archive_entry.h>
#include <fstream>
#include <chrono>
#include <format>
#include <thread>
#include <atomic>
#include <mutex>
#include <print>
#include <cstring>
#include <cerrno>
#include <ranges>
#include <iostream>
#include <csignal>
#include <system_error>

namespace fs = std::filesystem;

extern volatile std::sig_atomic_t gShutdownFlag;

/**
 * @brief Constructs a tar.gz backup strategy.
 *
 * @param excludeExtensions Extensions to exclude.
 * @param lastBackupFile Path to last backup timestamp file.
 */
TarGzFileBackupStrategy::TarGzFileBackupStrategy(const std::vector<std::string>& excludeExtensions, const std::string& lastBackupFile)
    : excludeExtensions(excludeExtensions), lastBackupFile(lastBackupFile) {}

/**
 * @brief Counts files to back up.
 *
 * @param sourceDirs Directories to scan.
 * @param fullBackup If true, ignores last backup time.
 * @return size_t Number of files to process.
 */
size_t TarGzFileBackupStrategy::countFiles(const std::vector<std::string>& sourceDirs, bool fullBackup) {
    size_t count = 0;
    std::chrono::system_clock::time_point lastBackupTime = std::chrono::system_clock::time_point();

    if (!fullBackup && fs::exists(lastBackupFile)) {
        std::ifstream file(lastBackupFile);
        std::string timestamp;
        if (std::getline(file, timestamp) && !timestamp.empty()) {
            try {
                lastBackupTime = std::chrono::system_clock::from_time_t(std::stol(timestamp));
            } catch (const std::exception& e) {
                std::println(stderr, "Warning: Invalid timestamp in {}: {}. Using default time (full backup).", lastBackupFile, e.what());
            }
        }
    }

    auto isExcluded = [this](const std::string& ext) {
        return !ext.empty() && std::ranges::find(excludeExtensions, ext) != excludeExtensions.end();
    };

    for (const auto& dir : sourceDirs) {
        if (!fs::exists(dir)) {
            std::cerr << "Warning: Directory does not exist, skipping: " << dir << std::endl;
            continue;
        }
        try {
            for (auto it = fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied);
                 it != fs::recursive_directory_iterator(); ++it) {
                if (it->is_regular_file()) {
                    auto ext = it->path().extension().string();
                    if (isExcluded(ext)) continue;
                    auto lastWrite = fs::last_write_time(*it);
                    auto fileTime = std::chrono::system_clock::now() - (std::chrono::system_clock::now() - std::chrono::file_clock::to_sys(lastWrite));
                    if (fullBackup || fileTime > lastBackupTime) {
                        ++count;
                    }
                }
            }
        } catch (const fs::filesystem_error& e) {
            std::cerr << "Warning: Failed to access directory " << dir << ": " << e.what() << ", skipping." << std::endl;
        }
    }
    return count;
}

/**
 * @brief Backs up a directory in a thread.
 *
 * @param dir Directory to back up.
 * @param outputFile Output .tar.gz file path (unused, kept for interface).
 * @param fullBackup If true, full backup.
 * @param archive Shared archive object.
 * @param processedFiles Processed file counter.
 * @param totalFiles Total files for progress.
 * @param mutex Thread-safe archive mutex.
 */
void TarGzFileBackupStrategy::backupDirectory(const std::string& dir,
                                              [[maybe_unused]] const std::string& outputFile,
                                              bool fullBackup,
                                              struct archive* archive,
                                              std::atomic<size_t>& processedFiles,
                                              size_t totalFiles,
                                              std::mutex& mutex,
                                              std::atomic<bool>& writeFailed) {
    std::ofstream logFile("backup_files.log", std::ios::app);
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    char timeBuf[32];
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&timeT));

    if (!fs::exists(dir)) {
        logFile << std::format("[{}] Warning: Directory does not exist, skipping: {}\n", timeBuf, dir);
        std::cerr << "Warning: Directory does not exist, skipping: " << dir << std::endl;
        return;
    }

    std::chrono::system_clock::time_point lastBackupTime = std::chrono::system_clock::time_point();
    if (!fullBackup && fs::exists(lastBackupFile)) {
        std::ifstream file(lastBackupFile);
        std::string timestamp;
        if (std::getline(file, timestamp) && !timestamp.empty()) {
            try {
                lastBackupTime = std::chrono::system_clock::from_time_t(std::stol(timestamp));
            } catch (const std::exception& e) {
                logFile << std::format("[{}] Warning: Invalid timestamp in {}: {}\n", timeBuf, lastBackupFile, e.what());
            }
        }
    }

    auto isExcluded = [this](const std::string& ext) {
        return !ext.empty() && std::ranges::find(excludeExtensions, ext) != excludeExtensions.end();
    };

    try {
        for (auto it = fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied);
             it != fs::recursive_directory_iterator(); ++it) {
            if (writeFailed) {
                break;
            }

            if (gShutdownFlag) {
                logFile << std::format("[{}] Warning: Backup interrupted by signal, stopping directory processing: {}\n", timeBuf, dir);
                std::cerr << "Warning: Backup interrupted by signal, stopping directory processing: " << dir << std::endl;
                break;
            }

            if (!it->is_regular_file()) continue;

            std::string path = it->path().string();
            auto ext = it->path().extension().string();
            if (isExcluded(ext)) continue;

            auto lastWrite = fs::last_write_time(*it);
            auto fileTime = std::chrono::system_clock::now() - (std::chrono::system_clock::now() - std::chrono::file_clock::to_sys(lastWrite));
            if (!fullBackup && fileTime <= lastBackupTime) continue;

            std::error_code relEc;
            fs::path relativePath = fs::relative(it->path(), dir, relEc);
            if (relEc || relativePath.empty()) {
                logFile << std::format("[{}] Warning: Failed to create relative path for {}, skipping.\n", timeBuf, path);
                continue;
            }

            fs::path archivePath = (fs::path(dir).filename() / relativePath).lexically_normal();
            if (archivePath.is_absolute() ||
                std::ranges::find(archivePath, fs::path("..")) != archivePath.end()) {
                logFile << std::format("[{}] Warning: Unsafe archive path derived from {}, skipping.\n", timeBuf, path);
                continue;
            }

            const std::string archivePathString = archivePath.generic_string();

            struct archive_entry* ae = archive_entry_new();
            archive_entry_set_pathname(ae, archivePathString.c_str());
            archive_entry_set_size(ae, it->file_size());
            archive_entry_set_filetype(ae, AE_IFREG);
            archive_entry_set_perm(ae, 0644);

            std::ifstream file(path, std::ios::binary);
            if (!file) {
                std::string errorMsg = std::format("Failed to open file: {} (error: {})", path, strerror(errno));
                logFile << std::format("[{}] {}\n", timeBuf, errorMsg);
                archive_entry_free(ae);
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(mutex);
                if (gShutdownFlag) {
                    archive_entry_free(ae);
                    file.close();
                    logFile << std::format("[{}] Warning: Backup interrupted by signal, stopping directory processing: {}\n", timeBuf, dir);
                    std::cerr << "Warning: Backup interrupted by signal, stopping directory processing: " << dir << std::endl;
                    return;
                }

                if (archive_write_header(archive, ae) != ARCHIVE_OK) {
                    logFile << std::format("[{}] Failed to write archive header for {} (error: {})\n",
                                           timeBuf,
                                           archivePathString,
                                           archive_error_string(archive));
                    writeFailed = true;
                    archive_entry_free(ae);
                    file.close();
                    break;
                }

                char buf[8192];
                while (file && !gShutdownFlag) {
                    file.read(buf, sizeof(buf));
                    std::streamsize bytesRead = file.gcount();
                    if (bytesRead <= 0) {
                        continue;
                    }

                    std::streamsize totalWritten = 0;
                    while (totalWritten < bytesRead) {
                        la_ssize_t written = archive_write_data(archive,
                                                                buf + totalWritten,
                                                                static_cast<size_t>(bytesRead - totalWritten));
                        if (written < 0) {
                            logFile << std::format("[{}] Failed to write archive data for {} (error: {})\n",
                                                   timeBuf,
                                                   archivePathString,
                                                   archive_error_string(archive));
                            writeFailed = true;
                            break;
                        }
                        totalWritten += written;
                    }

                    if (writeFailed) {
                        break;
                    }
                }

                if (file.bad()) {
                    logFile << std::format("[{}] Failed while reading file: {}\n", timeBuf, path);
                    writeFailed = true;
                }
            }
            archive_entry_free(ae);
            file.close();

            if (writeFailed) {
                break;
            }

            if (gShutdownFlag) {
                logFile << std::format("[{}] Warning: Backup interrupted by signal, stopping directory processing: {}\n", timeBuf, dir);
                std::cerr << "Warning: Backup interrupted by signal, stopping directory processing: " << dir << std::endl;
                break;
            }

            processedFiles++;
            float progress = std::min(static_cast<float>(processedFiles) / totalFiles * 100, 100.0f);
            std::print("\rProgress: {:.2f}% ({}/{} files)", progress, processedFiles.load(), totalFiles);
            logFile << std::format("[{}] Backed up: {}\n", timeBuf, path);
        }
    } catch (const fs::filesystem_error& e) {
        logFile << std::format("[{}] Warning: Failed to access directory {}: {}, skipping.\n", timeBuf, dir, e.what());
        std::cerr << "Warning: Failed to access directory " << dir << ": " << e.what() << ", skipping." << std::endl;
    }
}

/**
 * @brief Executes a tar.gz file backup.
 *
 * @param sourceDirs Directories to back up.
 * @param outputFile Output .tar.gz file path.
 * @param fullBackup If true, full backup.
 * @return std::expected<void, std::string> Success or error.
 */
std::expected<void, std::string> TarGzFileBackupStrategy::execute(const std::vector<std::string>& sourceDirs,
                                                                  const std::string& outputFile,
                                                                  bool fullBackup) {
    std::ofstream logFile("backup_files.log", std::ios::app);
    auto now = std::chrono::system_clock::now();
    auto timeT = std::chrono::system_clock::to_time_t(now);
    char timeBuf[32];
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&timeT));
    logFile << std::format("[{}] Starting backup to {}\n", timeBuf, outputFile);

    fs::path outputPath(outputFile);
    fs::create_directories(outputPath.parent_path());
    logFile << std::format("[{}] Created output directory: {}\n", timeBuf, outputPath.parent_path().string());

    std::println("Counting files...");
    size_t totalFiles = countFiles(sourceDirs, fullBackup);
    if (totalFiles == 0) {
        logFile << std::format("[{}] Warning: No files to back up.\n", timeBuf);
        std::cerr << "Warning: No files to back up." << std::endl;
        return {};
    }

    std::atomic<size_t> processedFiles(0);
    std::atomic<bool> writeFailed(false);
    std::mutex archiveMutex;

    struct archive* a = archive_write_new();
    archive_write_add_filter_gzip(a);
    archive_write_set_format_pax_restricted(a);
    int result = archive_write_open_filename(a, outputFile.c_str());
    if (result != ARCHIVE_OK) {
        std::string errorMsg = std::format("Failed to open archive file: {} (error: {})", outputFile, archive_error_string(a));
        archive_write_free(a);
        logFile << std::format("[{}] {}\n", timeBuf, errorMsg);
        return std::unexpected(errorMsg);
    }

    std::vector<std::thread> threads;
    for (const auto& dir : sourceDirs) {
        threads.emplace_back([this, &dir, &outputFile, fullBackup, a, &processedFiles, totalFiles, &archiveMutex, &writeFailed]() {
            this->backupDirectory(dir, outputFile, fullBackup, a, processedFiles, totalFiles, archiveMutex, writeFailed);
        });
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    if (gShutdownFlag) {
        logFile << std::format("[{}] Warning: Backup interrupted by signal, closing archive.\n", timeBuf);
        std::cerr << "Warning: Backup interrupted by signal, closing archive." << std::endl;
        archive_write_close(a);
        archive_write_free(a);
        return std::unexpected("Backup interrupted by signal");
    }

    if (writeFailed) {
        logFile << std::format("[{}] Error: Backup failed due to archive write errors.\n", timeBuf);
        archive_write_close(a);
        archive_write_free(a);
        return std::unexpected("Backup failed due to archive write errors");
    }

    archive_write_close(a);
    archive_write_free(a);
    logFile << std::format("[{}] File backup completed: {}\n", timeBuf, outputFile);
    logFile.close();
    std::println("\nFile backup completed.");

    now = std::chrono::system_clock::now();
    timeT = std::chrono::system_clock::to_time_t(now);
    std::ofstream lastBackup(lastBackupFile);
    lastBackup << timeT;
    lastBackup.close();

    return {};
}
