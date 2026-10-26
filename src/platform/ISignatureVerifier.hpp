#pragma once

#include "core/CancellationToken.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>

namespace sectoryn {

enum class SignatureState : std::uint8_t {
    // The embedded signature verified and chains to a trusted root.
    Verified,
    // The file carries no Authenticode signature.
    Unsigned,
    // A signature exists but the file was modified after signing or the signature is corrupt.
    Invalid,
    // The signature is intact but its certificate is not trusted, expired or revoked.
    Untrusted,
    // Verification could not be completed, e.g. on a platform without Authenticode support.
    Unavailable,
};

[[nodiscard]] std::string_view toString(SignatureState state) noexcept;

struct SignatureVerification {
    SignatureState state = SignatureState::Unavailable;
    // Text from the platform explaining the state; never empty.
    std::string detail;
    // Certificate fields are untrusted metadata unless the state is Verified.
    std::string signer;
    std::string issuer;
    std::string serialNumber;
    // Only revocation information already cached on the machine is used, so the check never
    // waits on the network.
    bool usedCachedRevocationOnly = true;
};

// Verifies Authenticode signatures. Implementations read the file and never load or run it.
class ISignatureVerifier {
public:
    virtual ~ISignatureVerifier() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    // False when every verification would return Unavailable.
    [[nodiscard]] virtual bool supported() const noexcept = 0;
    // Safe to call from several threads at once.
    [[nodiscard]] virtual SignatureVerification verify(const std::filesystem::path& path,
                                                       const CancellationToken& token) const = 0;

protected:
    ISignatureVerifier() = default;
    ISignatureVerifier(const ISignatureVerifier&) = default;
    ISignatureVerifier& operator=(const ISignatureVerifier&) = default;
    ISignatureVerifier(ISignatureVerifier&&) = default;
    ISignatureVerifier& operator=(ISignatureVerifier&&) = default;
};

// The verifier for the current platform. On platforms without one it returns a verifier that
// reports every file as Unavailable with the reason.
[[nodiscard]] std::unique_ptr<ISignatureVerifier> createPlatformSignatureVerifier();

} // namespace sectoryn
