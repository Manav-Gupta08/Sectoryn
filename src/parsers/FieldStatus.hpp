#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace sectoryn {

// Records how much is known about a PE structure. The default is NotInspected so that a
// structure nobody looked at can never be mistaken for one that is confirmed to be absent.
enum class FieldState : std::uint8_t {
    NotInspected,
    Present,
    Absent,
    Invalid,
    Unsupported,
    ParserError,
    Incomplete,
};

[[nodiscard]] constexpr std::string_view toString(FieldState state) noexcept {
    switch (state) {
    case FieldState::NotInspected:
        return "not inspected";
    case FieldState::Present:
        return "present";
    case FieldState::Absent:
        return "absent";
    case FieldState::Invalid:
        return "invalid";
    case FieldState::Unsupported:
        return "unsupported";
    case FieldState::ParserError:
        return "parser error";
    case FieldState::Incomplete:
        return "incomplete";
    }
    return "unknown";
}

struct FieldStatus {
    FieldState state = FieldState::NotInspected;
    std::string detail;

    [[nodiscard]] static FieldStatus present() { return {FieldState::Present, {}}; }
    [[nodiscard]] static FieldStatus absent(std::string why) {
        return {FieldState::Absent, std::move(why)};
    }
    [[nodiscard]] static FieldStatus invalid(std::string why) {
        return {FieldState::Invalid, std::move(why)};
    }
    [[nodiscard]] static FieldStatus parserError(std::string why) {
        return {FieldState::ParserError, std::move(why)};
    }
    [[nodiscard]] static FieldStatus incomplete(std::string why) {
        return {FieldState::Incomplete, std::move(why)};
    }

    // True when at least part of the structure was read and can be shown.
    [[nodiscard]] bool hasData() const noexcept {
        return state == FieldState::Present || state == FieldState::Incomplete;
    }
};

} // namespace sectoryn
