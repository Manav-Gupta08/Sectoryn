#pragma once

#include "platform/ISignatureVerifier.hpp"

namespace sectoryn {

// WinVerifyTrust with the Authenticode policy. Revocation is checked only against data already
// cached by Windows, and no user interface is ever shown.
class AuthenticodeVerifier final : public ISignatureVerifier {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "WinVerifyTrust"; }
    [[nodiscard]] bool supported() const noexcept override { return true; }

    [[nodiscard]] SignatureVerification verify(const std::filesystem::path& path,
                                               const CancellationToken& token) const override;
};

} // namespace sectoryn
