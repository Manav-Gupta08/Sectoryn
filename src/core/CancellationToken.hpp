#pragma once

#include "core/Result.hpp"

#include <stop_token>

namespace sectoryn {

// Cancellation is cooperative and built on std::stop_source / std::stop_token. A
// default-constructed token can never be cancelled, which suits synchronous callers.
using CancellationSource = std::stop_source;
using CancellationToken = std::stop_token;

[[nodiscard]] inline Status checkCancelled(const CancellationToken& token) {
    if (token.stop_requested()) {
        return Error{ErrorCode::Cancelled, "operation cancelled"};
    }
    return {};
}

} // namespace sectoryn
