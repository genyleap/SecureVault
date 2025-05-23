#include "notification.hpp"
#include <curl/curl.h>
#include <print>
#include <format>

size_t writeCallback([[maybe_unused]] void* contents, size_t size, size_t nmemb, [[maybe_unused]] void* userp) {
    return size * nmemb;
}

TelegramNotificationStrategy::TelegramNotificationStrategy(const Json::Value& config)
    : botToken(config["bot_token"].asString()), chatId(config["chat_id"].asString()) {}

std::expected<void, std::string> TelegramNotificationStrategy::notify(const std::string& message) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return std::unexpected("Failed to initialize CURL");
    }

    std::string escapedMessage = curl_easy_escape(curl, message.c_str(), message.length());
    std::string url = std::format("https://api.telegram.org/bot{}/sendMessage?chat_id={}&text={}",
        botToken, chatId, escapedMessage);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        return std::unexpected(std::format("Failed to send Telegram notification: {}", curl_easy_strerror(res)));
    }

    curl_easy_cleanup(curl);
    return {};
}

EmailNotificationStrategy::EmailNotificationStrategy(const Json::Value& config)
    : emailTo(config["email_to"].asString()), smtpServer(config["smtp_server"].asString()) {}

std::expected<void, std::string> EmailNotificationStrategy::notify(const std::string& message) {
    std::println("Simulated email sent to {} via {}: {}", emailTo, smtpServer, message);
    return {};
}