#include "platform/ISignatureVerifier.hpp"

namespace sectoryn {

std::string_view toString(SignatureState state) noexcept {
    switch (state) {
    case SignatureState::Verified:
        return "verified";
    case SignatureState::Unsigned:
        return "unsigned";
    case SignatureState::Invalid:
        return "invalid";
    case SignatureState::Untrusted:
        return "untrusted";
    case SignatureState::Unavailable:
        return "unavailable";
    }
    return "unknown";
}

} // namespace sectoryn
