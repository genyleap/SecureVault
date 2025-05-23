#include "backup_api.hpp"
#include "backup.hpp"
#include <fstream>

std::expected<void, std::string> BackupAPI::startBackup(const std::string& type, bool fullBackup) {
    try {
        Backup backup("backup_config.json");
        return backup.execute(type, fullBackup);
    } catch (const std::exception& e) {
        return std::unexpected(std::format("Failed to start backup: {}", e.what()));
    }
}

std::expected<void, std::string> BackupAPI::updateSchedule(const Json::Value& schedule) {
    try {
        std::string configFile = "backup_config.json";
        std::ifstream file(configFile);
        if (!file.is_open()) {
            return std::unexpected("Failed to open config file for reading: " + configFile);
        }
        Json::Value configJson;
        Json::Reader reader;
        if (!reader.parse(file, configJson)) {
            return std::unexpected("Failed to parse config file: " + configFile);
        }
        file.close();

        configJson["schedule"] = schedule;

        std::ofstream outFile(configFile);
        if (!outFile.is_open()) {
            return std::unexpected("Failed to open config file for writing: " + configFile);
        }
        Json::StreamWriterBuilder builder;
        std::unique_ptr<Json::StreamWriter> writer(builder.newStreamWriter());
        writer->write(configJson, &outFile);
        outFile.close();

        return {};
    } catch (const std::exception& e) {
        return std::unexpected(std::format("Failed to update schedule: {}", e.what()));
    }
}
