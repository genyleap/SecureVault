#include "remote_transfer.hpp"

SFTPTransferStrategy::SFTPTransferStrategy(const Json::Value& config)
    : host_(config.get("host", "").asString()),
      user_(config.get("user", "").asString()),
      password_(config.get("password", "").asString()),
      port_(config.get("port", 22).asInt()),
      remote_dir_(config.isMember("remote_dir")
                      ? config["remote_dir"].asString()
                      : config.get("remote_path", "").asString()) {}

std::expected<void, std::string> SFTPTransferStrategy::transfer(const std::string& local_file, const std::string& remote_path) {
    (void)local_file;
    (void)remote_path;
    return std::unexpected("SFTP support is disabled in this build because libssh was not found");
}
