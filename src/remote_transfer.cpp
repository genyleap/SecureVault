#include "remote_transfer.hpp"
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <fcntl.h>

namespace fs = std::filesystem;

SFTPTransferStrategy::SFTPTransferStrategy(const Json::Value& config)
    : host_(config["host"].asString()),
      user_(config["user"].asString()),
      password_(config["password"].asString()),
      port_(config["port"].asInt()),
      remote_dir_(config["remote_dir"].asString()) {}

std::expected<void, std::string> SFTPTransferStrategy::transfer(const std::string& local_file, const std::string& remote_path) {
    ssh_session ssh = ssh_new();
    if (!ssh) {
        return std::unexpected("Failed to create SSH session");
    }
    ssh_options_set(ssh, SSH_OPTIONS_HOST, host_.c_str());
    ssh_options_set(ssh, SSH_OPTIONS_PORT, &port_);
    ssh_options_set(ssh, SSH_OPTIONS_USER, user_.c_str());
    if (ssh_connect(ssh) != SSH_OK) {
        ssh_free(ssh);
        return std::unexpected("SSH connection failed");
    }

    if (password_.empty()) {
        if (ssh_userauth_publickey_auto(ssh, nullptr, nullptr) != SSH_AUTH_SUCCESS) {
            ssh_disconnect(ssh);
            ssh_free(ssh);
            return std::unexpected("SSH authentication failed");
        }
    } else {
        if (ssh_userauth_password(ssh, nullptr, password_.c_str()) != SSH_AUTH_SUCCESS) {
            ssh_disconnect(ssh);
            ssh_free(ssh);
            return std::unexpected("SSH password authentication failed");
        }
    }

    sftp_session sftp = sftp_new(ssh);
    if (!sftp || sftp_init(sftp) != SSH_OK) {
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return std::unexpected("SFTP initialization failed");
    }

    std::string remote_file = remote_path + "/" + fs::path(local_file).filename().string();
    sftp_file file = sftp_open(sftp, remote_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!file) {
        sftp_free(sftp);
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return std::unexpected("Failed to open remote file");
    }

    std::ifstream input_file(local_file, std::ios::binary);
    if (!input_file) {
        sftp_close(file);
        sftp_free(sftp);
        ssh_disconnect(ssh);
        ssh_free(ssh);
        return std::unexpected("Failed to open local file");
    }

    char buf[8192];
    while (input_file) {
        input_file.read(buf, sizeof(buf));
        sftp_write(file, buf, input_file.gcount());
    }

    sftp_close(file);
    sftp_free(sftp);
    ssh_disconnect(ssh);
    ssh_free(ssh);
    std::cout << "Transferred file to remote: " << remote_file << std::endl;
    return {};
}