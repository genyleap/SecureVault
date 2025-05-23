/**
 * @file notification.hpp
 * @brief Defines notification strategies for SecureVault.
 *
 * Provides interfaces and implementations for sending backup status notifications via
 * Telegram and email. Designed for cross-platform use, with dependencies managed via libcurl.
 *
 * @note Requires libcurl for Telegram and email notifications. Install via vcpkg on Windows,
 * Homebrew on macOS, or apt on Linux.
 */

#ifndef NOTIFICATION_HPP
#define NOTIFICATION_HPP

#include <string>
#include <expected>
#include <json/json.h>

/**
 * @brief Interface for notification strategies.
 *
 * Defines the contract for sending notifications about backup status.
 */
class NotificationStrategy {
public:
    /**
     * @brief Virtual destructor for safe polymorphism.
     */
    virtual ~NotificationStrategy() = default;

    /**
     * @brief Sends a notification.
     *
     * Delivers the specified message via the configured notification channel.
     *
     * @param message Message to send.
     * @return std::expected<void, std::string> Success or an error message.
     */
    virtual std::expected<void, std::string> notify(const std::string& message) = 0;
};

/**
 * @brief Telegram notification strategy.
 *
 * Sends notifications using the Telegram Bot API.
 */
class TelegramNotificationStrategy : public NotificationStrategy {
public:
    /**
     * @brief Constructs a Telegram notification strategy.
     *
     * @param config JSON configuration with bot_token and chat_id.
     * @throws std::runtime_error If configuration is invalid.
     */
    explicit TelegramNotificationStrategy(const Json::Value& config);

    /**
     * @brief Sends a notification via Telegram.
     *
     * Sends the message to the configured Telegram chat.
     *
     * @param message Message to send.
     * @return std::expected<void, std::string> Success or an error message.
     */
    std::expected<void, std::string> notify(const std::string& message) override;

private:
    std::string botToken; ///< Telegram bot token.
    std::string chatId; ///< Telegram chat ID.
};

/**
 * @brief Email notification strategy.
 *
 * Sends notifications using SMTP email.
 */
class EmailNotificationStrategy : public NotificationStrategy {
public:
    /**
     * @brief Constructs an email notification strategy.
     *
     * @param config JSON configuration with email_to, smtp_server, and optional credentials.
     * @throws std::runtime_error If configuration is invalid.
     */
    explicit EmailNotificationStrategy(const Json::Value& config);

    /**
     * @brief Sends a notification via email.
     *
     * Sends the message to the configured email address.
     *
     * @param message Message to send.
     * @return std::expected<void, std::string> Success or an error message.
     */
    std::expected<void, std::string> notify(const std::string& message) override;

private:
    std::string emailTo; ///< Recipient email address.
    std::string smtpServer; ///< SMTP server address.
};

#endif // NOTIFICATION_HPP
