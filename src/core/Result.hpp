#pragma once

#include "core/Error.hpp"

#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace sectoryn {

// Minimal C++20 stand-in for std::expected<T, Error>.
template <typename T>
class [[nodiscard]] Result {
    static_assert(!std::is_same_v<std::remove_cvref_t<T>, Error>,
                  "Result<Error> is ambiguous; use Result<void> instead");
    static_assert(!std::is_reference_v<T>, "Result does not hold references");

public:
    using value_type = T;

    // NOLINTNEXTLINE(google-explicit-constructor): implicit success conversion is intentional.
    Result(T value)
        : storage_(std::in_place_index<0>, std::move(value)) {}

    // NOLINTNEXTLINE(google-explicit-constructor): implicit failure conversion is intentional.
    Result(Error error)
        : storage_(std::in_place_index<1>, std::move(error)) {}

    [[nodiscard]] bool hasValue() const noexcept { return storage_.index() == 0; }
    [[nodiscard]] explicit operator bool() const noexcept { return hasValue(); }

    // Accessing the wrong alternative throws std::bad_variant_access.
    [[nodiscard]] T& value() & { return std::get<0>(storage_); }
    [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
    [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

    [[nodiscard]] const Error& error() const& { return std::get<1>(storage_); }
    [[nodiscard]] Error&& error() && { return std::get<1>(std::move(storage_)); }

    template <typename U>
    [[nodiscard]] T valueOr(U&& fallback) const& {
        return hasValue() ? value() : static_cast<T>(std::forward<U>(fallback));
    }

    template <typename U>
    [[nodiscard]] T valueOr(U&& fallback) && {
        return hasValue() ? std::move(*this).value() : static_cast<T>(std::forward<U>(fallback));
    }

private:
    std::variant<T, Error> storage_;
};

template <>
class [[nodiscard]] Result<void> {
public:
    Result() = default;

    // NOLINTNEXTLINE(google-explicit-constructor): implicit failure conversion is intentional.
    Result(Error error)
        : error_(std::move(error)) {}

    [[nodiscard]] bool hasValue() const noexcept { return !error_.has_value(); }
    [[nodiscard]] explicit operator bool() const noexcept { return hasValue(); }

    [[nodiscard]] const Error& error() const& { return error_.value(); }
    [[nodiscard]] Error&& error() && { return std::move(error_).value(); }

private:
    std::optional<Error> error_;
};

using Status = Result<void>;

} // namespace sectoryn
