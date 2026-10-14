#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace sectoryn {

// Categories are kept coarse so the UI can choose a presentation without parsing messages.
enum class ErrorCode : std::uint8_t {
    InvalidInput,
    UnsupportedFormat,
    MalformedData,
    ParserFailure,
    Cancelled,
    ResourceLimitExceeded,
    IoFailure,
    ExternalServiceFailure,
    Internal,
};

[[nodiscard]] constexpr std::string_view toString(ErrorCode code) noexcept {
    switch (code) {
    case ErrorCode::InvalidInput:
        return "invalid input";
    case ErrorCode::UnsupportedFormat:
        return "unsupported format";
    case ErrorCode::MalformedData:
        return "malformed data";
    case ErrorCode::ParserFailure:
        return "parser failure";
    case ErrorCode::Cancelled:
        return "cancelled";
    case ErrorCode::ResourceLimitExceeded:
        return "resource limit exceeded";
    case ErrorCode::IoFailure:
        return "I/O failure";
    case ErrorCode::ExternalServiceFailure:
        return "external service failure";
    case ErrorCode::Internal:
        return "internal error";
    }
    return "unknown error";
}

struct Error {
    ErrorCode code = ErrorCode::Internal;
    std::string message;

    Error() = default;
    Error(ErrorCode errorCode, std::string errorMessage)
        : code(errorCode)
        , message(std::move(errorMessage)) {}

    [[nodiscard]] std::string describe() const {
        std::string text(toString(code));
        if (!message.empty()) {
            text += ": ";
            text += message;
        }
        return text;
    }
};

} // namespace sectoryn
