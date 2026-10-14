#pragma once

#include "core/Result.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <ostream>
#include <string>
#include <string_view>

namespace sectoryn {

enum class LogLevel : std::uint8_t { Debug, Info, Warning, Error, Off };

[[nodiscard]] std::string_view toString(LogLevel level) noexcept;

// Thread-safe logger with an optional size-bounded file sink.
class Logger {
public:
    static constexpr std::size_t kMaxMessageBytes = 4096;

    explicit Logger(LogLevel level = LogLevel::Info, std::ostream* console = nullptr);

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;
    ~Logger() = default;

    void setLevel(LogLevel level) noexcept;
    [[nodiscard]] LogLevel level() const noexcept;
    [[nodiscard]] bool isEnabled(LogLevel level) const noexcept;

    // When the file would grow past maxBytes it is rotated to "<path>.1" (one backup kept).
    [[nodiscard]] Status openFile(const std::filesystem::path& path, std::uintmax_t maxBytes);
    void closeFile();

    void log(LogLevel level, std::string_view message);
    void debug(std::string_view message) { log(LogLevel::Debug, message); }
    void info(std::string_view message) { log(LogLevel::Info, message); }
    void warning(std::string_view message) { log(LogLevel::Warning, message); }
    void error(std::string_view message) { log(LogLevel::Error, message); }

    // Replaces control characters so untrusted text cannot forge extra log lines.
    [[nodiscard]] static std::string sanitize(std::string_view message);

private:
    void rotateIfNeeded(std::size_t incomingBytes);

    std::atomic<LogLevel> level_;
    std::mutex mutex_;
    std::ostream* console_;
    std::ofstream file_;
    std::filesystem::path filePath_;
    std::uintmax_t maxFileBytes_ = 0;
    std::uintmax_t fileBytes_ = 0;
};

} // namespace sectoryn
