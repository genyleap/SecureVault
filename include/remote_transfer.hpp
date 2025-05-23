/**
 * @file remote_transfer.hpp
 * @brief Defines remote transfer strategies for SecureVault.
 *
 * Provides interfaces and implementations for transferring backup files to remote locations,
 * with a focus on SFTP. Designed for cross-platform use, with dependencies managed via libssh.
 *
 * @note Requires libssh for SFTP transfers. Install via vcpkg on Windows, Homebrew on macOS,
 * or apt on Linux.
 */

#ifndef REMOTE_TRANSFER_HPP
#define REMOTE_TRANSFER_HPP

#include <string>
#include <expected>
#include <json/json.h>

/**
 * @brief Interface for remote transfer strategies.
 *
 * Defines the contract for transferring backup files to remote destinations.
 */
class RemoteTransferStrategy {
public:
    /**
     * @brief Virtual destructor for safe polymorphism.
     */
    virtual ~RemoteTransferStrategy() = default;

    /**
     * @brief Transfers a local file to a remote location.
     *
     * Sends the specified file to the configured remote destination.
     *
     * @param local_file Path to the local file.
     * @param remote_path Remote directory path.
     * @return std::expected<void, std::string> Success or an error message.
     * @note Ensure remote paths are platform-appropriate (e.g., "/backups/" on Linux, "\\backups\\" on Windows).
     */
    virtual std::expected<void, std::string> transfer(const std::string& local_file, const std::string& remote_path) = 0;
};

/**
 * @brief SFTP remote transfer strategy.
 *
 * Implements file transfers using the SFTP protocol, suitable for secure remote backups.
 */
class SFTPTransferStrategy : public RemoteTransferStrategy {
public:
    /**
     * @brief Constructs an SFTP transfer strategy.
     *
     * @param config JSON configuration containing host, user, password, port, and remote_dir.
     * @throws std::runtime_error If configuration is invalid.
     */
    explicit SFTPTransferStrategy(const Json::Value& config);

    /**
     * @brief Transfers a file via SFTP.
     *
     * Sends the local file to the specified remote directory using SFTP.
     *
     * @param local_file Path to the local file.
     * @param remote_path Remote directory path.
     * @return std::expected<void, std::string> Success or an error message.
     */
    std::expected<void, std::string> transfer(const std::string& local_file, const std::string& remote_path) override;

private:
    std::string host_; ///< SFTP host address.
    std::string user_; ///< SFTP username.
    std::string password_; ///< SFTP password.
    int port_; ///< SFTP port (e.g., 22).
    std::string remote_dir_; ///< Remote directory for backups.
};

#endif // REMOTE_TRANSFER_HPP
