#include "core/Logger.hpp"

#include <chrono>
#include <format>
#include <system_error>

namespace sectoryn {

namespace {

std::string timestamp() {
    const auto now =
        std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
    return std::format("{:%FT%T}Z", now);
}

} // namespace

std::string_view toString(LogLevel level) noexcept {
    switch (level) {
    case LogLevel::Debug:
        return "DEBUG";
    case LogLevel::Info:
        return "INFO";
    case LogLevel::Warning:
        return "WARN";
    case LogLevel::Error:
        return "ERROR";
    case LogLevel::Off:
        return "OFF";
    }
    return "UNKNOWN";
}

Logger::Logger(LogLevel level, std::ostream* console)
    : level_(level)
    , console_(console) {}

void Logger::setLevel(LogLevel level) noexcept {
    level_.store(level, std::memory_order_relaxed);
}

LogLevel Logger::level() const noexcept {
    return level_.load(std::memory_order_relaxed);
}

bool Logger::isEnabled(LogLevel level) const noexcept {
    const LogLevel threshold = this->level();
    return level != LogLevel::Off && threshold != LogLevel::Off && level >= threshold;
}

Status Logger::openFile(const std::filesystem::path& path, std::uintmax_t maxBytes) {
    if (path.empty()) {
        return Error{ErrorCode::InvalidInput, "log file path is empty"};
    }
    if (maxBytes == 0) {
        return Error{ErrorCode::InvalidInput, "log file size limit must be greater than zero"};
    }

    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return Error{ErrorCode::IoFailure, "cannot create log directory: " + ec.message()};
        }
    }

    const std::scoped_lock lock(mutex_);
    file_.close();
    file_.open(path, std::ios::out | std::ios::app | std::ios::binary);
    if (!file_.is_open()) {
        return Error{ErrorCode::IoFailure, "cannot open log file"};
    }

    const std::uintmax_t existing = std::filesystem::file_size(path, ec);
    fileBytes_ = ec ? 0 : existing;
    filePath_ = path;
    maxFileBytes_ = maxBytes;
    return {};
}

void Logger::closeFile() {
    const std::scoped_lock lock(mutex_);
    file_.close();
    filePath_.clear();
    fileBytes_ = 0;
    maxFileBytes_ = 0;
}

void Logger::log(LogLevel level, std::string_view message) {
    if (!isEnabled(level)) {
        return;
    }

    const std::string line =
        std::format("{} [{}] {}\n", timestamp(), toString(level), sanitize(message));

    const std::scoped_lock lock(mutex_);
    if (console_ != nullptr) {
        *console_ << line;
    }
    if (file_.is_open()) {
        rotateIfNeeded(line.size());
        file_ << line;
        file_.flush();
        fileBytes_ += line.size();
    }
}

std::string Logger::sanitize(std::string_view message) {
    constexpr std::string_view kTruncationMarker = "...[truncated]";
    const bool truncated = message.size() > kMaxMessageBytes;
    if (truncated) {
        message = message.substr(0, kMaxMessageBytes);
    }

    std::string out;
    out.reserve(message.size() + (truncated ? kTruncationMarker.size() : 0));
    for (const char c : message) {
        const auto byte = static_cast<unsigned char>(c);
        const bool control = (byte < 0x20 && c != '\t') || byte == 0x7F;
        out.push_back(control ? '?' : c);
    }
    if (truncated) {
        out += kTruncationMarker;
    }
    return out;
}

void Logger::rotateIfNeeded(std::size_t incomingBytes) {
    if (fileBytes_ == 0 || fileBytes_ + incomingBytes <= maxFileBytes_) {
        return;
    }

    file_.close();
    std::filesystem::path backup = filePath_;
    backup += ".1";

    std::error_code ec;
    std::filesystem::remove(backup, ec);
    std::filesystem::rename(filePath_, backup, ec);
    // If rotation fails the file is truncated instead, so the size bound still holds.
    file_.open(filePath_, std::ios::out | std::ios::trunc | std::ios::binary);
    fileBytes_ = 0;
}

} // namespace sectoryn
