#include "remote_transfer.hpp"
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <format>
#include <sstream>
#include <algorithm>
#include <fcntl.h>

namespace fs = std::filesystem;

namespace {

std::string normalizeRemotePath(std::string path) {
    std::replace(path.begin(), path.end(), '\\', '/');
    while (path.size() > 1 && path.back() == '/') {
        path.pop_back();
    }
    return path;
}

std::string joinRemotePath(const std::string& base, const std::string& leaf) {
    if (leaf.empty()) {
        return normalizeRemotePath(base);
    }

    std::string normalizedLeaf = normalizeRemotePath(leaf);
    if (!normalizedLeaf.empty() && normalizedLeaf.front() == '/') {
        return normalizedLeaf;
    }

    std::string normalizedBase = normalizeRemotePath(base);
    if (normalizedBase.empty()) {
        return normalizedLeaf;
    }
    if (normalizedBase == "/") {
        return "/" + normalizedLeaf;
    }
    return normalizedBase + "/" + normalizedLeaf;
}

std::string knownHostStatusToString(int status) {
    switch (status) {
        case SSH_KNOWN_HOSTS_OK:
            return "trusted";
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            return "known_hosts file not found";
        case SSH_KNOWN_HOSTS_UNKNOWN:
            return "server host key is unknown";
        case SSH_KNOWN_HOSTS_CHANGED:
            return "server host key changed";
        case SSH_KNOWN_HOSTS_OTHER:
            return "server host key type mismatch";
        case SSH_KNOWN_HOSTS_ERROR:
            return "host key verification error";
        default:
            return "unknown host verification state";
    }
}

std::expected<void, std::string> verifyHostKey(ssh_session ssh) {
    const int knownState = ssh_session_is_known_server(ssh);
    if (knownState == SSH_KNOWN_HOSTS_OK) {
        return {};
    }
    return std::unexpected(std::format("SSH host key verification failed: {}", knownHostStatusToString(knownState)));
}

std::expected<void, std::string> ensureRemoteDirectories(sftp_session sftp, const std::string& directory) {
    std::string normalized = normalizeRemotePath(directory);
    if (normalized.empty()) {
        return std::unexpected("Remote destination directory is empty");
    }

    std::string current = normalized.starts_with('/') ? "/" : "";
    std::stringstream ss(normalized);
    std::string segment;
    while (std::getline(ss, segment, '/')) {
        if (segment.empty() || segment == ".") {
            continue;
        }

        if (!current.empty() && current != "/") {
            current += "/";
        }
        current += segment;

        if (sftp_mkdir(sftp, current.c_str(), 0700) == SSH_ERROR) {
            const int sftpError = sftp_get_error(sftp);
            if (sftpError != SSH_FX_FILE_ALREADY_EXISTS) {
                return std::unexpected(std::format("Failed to create remote directory '{}', SFTP error {}", current, sftpError));
            }
        }
    }

    return {};
}

} // namespace

SFTPTransferStrategy::SFTPTransferStrategy(const Json::Value& config)
    : host_(config.get("host", "").asString()),
      user_(config.get("user", "").asString()),
      password_(config.get("password", "").asString()),
      port_(config.get("port", 22).asInt()),
      remote_dir_(config.isMember("remote_dir")
                      ? config["remote_dir"].asString()
                      : config.get("remote_path", "").asString()) {}

std::expected<void, std::string> SFTPTransferStrategy::transfer(const std::string& local_file, const std::string& remote_path) {
    if (host_.empty() || user_.empty() || port_ <= 0) {
        return std::unexpected("Invalid SFTP configuration: host, user, or port missing");
    }

    std::ifstream input_file(local_file, std::ios::binary);
    if (!input_file) {
        return std::unexpected("Failed to open local file");
    }

    std::string destinationDir = remote_path.empty()
        ? remote_dir_
        : joinRemotePath(remote_dir_, remote_path);
    destinationDir = normalizeRemotePath(destinationDir);
    if (destinationDir.empty()) {
        return std::unexpected("No remote destination directory configured");
    }

    ssh_session ssh = ssh_new();
    sftp_session sftp = nullptr;
    sftp_file file = nullptr;
    auto cleanup = [&]() {
        if (file) {
            sftp_close(file);
            file = nullptr;
        }
        if (sftp) {
            sftp_free(sftp);
            sftp = nullptr;
        }
        if (ssh) {
            ssh_disconnect(ssh);
            ssh_free(ssh);
            ssh = nullptr;
        }
    };

    if (!ssh) {
        return std::unexpected("Failed to create SSH session");
    }

    if (ssh_options_set(ssh, SSH_OPTIONS_HOST, host_.c_str()) != SSH_OK ||
        ssh_options_set(ssh, SSH_OPTIONS_PORT, &port_) != SSH_OK ||
        ssh_options_set(ssh, SSH_OPTIONS_USER, user_.c_str()) != SSH_OK) {
        const std::string error = ssh_get_error(ssh);
        cleanup();
        return std::unexpected(std::format("Failed to configure SSH session: {}", error));
    }

    if (ssh_connect(ssh) != SSH_OK) {
        const std::string error = ssh_get_error(ssh);
        cleanup();
        return std::unexpected(std::format("SSH connection failed: {}", error));
    }

    auto hostVerify = verifyHostKey(ssh);
    if (!hostVerify) {
        cleanup();
        return std::unexpected(hostVerify.error());
    }

    if (password_.empty()) {
        if (ssh_userauth_publickey_auto(ssh, nullptr, nullptr) != SSH_AUTH_SUCCESS) {
            const std::string error = ssh_get_error(ssh);
            cleanup();
            return std::unexpected(std::format("SSH public key authentication failed: {}", error));
        }
    } else {
        if (ssh_userauth_password(ssh, nullptr, password_.c_str()) != SSH_AUTH_SUCCESS) {
            const std::string error = ssh_get_error(ssh);
            cleanup();
            return std::unexpected(std::format("SSH password authentication failed: {}", error));
        }
    }

    sftp = sftp_new(ssh);
    if (!sftp) {
        const std::string error = ssh_get_error(ssh);
        cleanup();
        return std::unexpected(std::format("Failed to create SFTP session: {}", error));
    }
    if (sftp_init(sftp) != SSH_OK) {
        const std::string error = ssh_get_error(ssh);
        cleanup();
        return std::unexpected(std::format("SFTP initialization failed: {}", error));
    }

    auto mkdirResult = ensureRemoteDirectories(sftp, destinationDir);
    if (!mkdirResult) {
        cleanup();
        return std::unexpected(mkdirResult.error());
    }

    const std::string remote_file = joinRemotePath(destinationDir, fs::path(local_file).filename().string());
    file = sftp_open(sftp, remote_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!file) {
        const std::string error = ssh_get_error(ssh);
        cleanup();
        return std::unexpected(std::format("Failed to open remote file '{}': {}", remote_file, error));
    }

    char buf[8192];
    while (input_file) {
        input_file.read(buf, sizeof(buf));
        std::streamsize bytesRead = input_file.gcount();
        if (bytesRead <= 0) {
            continue;
        }

        std::streamsize totalWritten = 0;
        while (totalWritten < bytesRead) {
            const int written = sftp_write(file,
                                           buf + totalWritten,
                                           static_cast<size_t>(bytesRead - totalWritten));
            if (written < 0) {
                const std::string error = ssh_get_error(ssh);
                cleanup();
                return std::unexpected(std::format("Failed to write remote file '{}': {}", remote_file, error));
            }
            totalWritten += written;
        }
    }

    if (input_file.bad()) {
        cleanup();
        return std::unexpected("Failed while reading local file for transfer");
    }

    if (sftp_close(file) != SSH_OK) {
        file = nullptr;
        const std::string error = ssh_get_error(ssh);
        cleanup();
        return std::unexpected(std::format("Failed to finalize remote file '{}': {}", remote_file, error));
    }
    file = nullptr;

    cleanup();
    std::cout << "Transferred file to remote: " << remote_file << std::endl;
    return {};
}
