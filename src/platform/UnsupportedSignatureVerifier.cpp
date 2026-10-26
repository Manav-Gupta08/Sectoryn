#include "platform/ISignatureVerifier.hpp"

#ifndef SECTORYN_HAVE_AUTHENTICODE

namespace sectoryn {

namespace {

class UnsupportedSignatureVerifier final : public ISignatureVerifier {
public:
    [[nodiscard]] std::string_view name() const noexcept override { return "none"; }
    [[nodiscard]] bool supported() const noexcept override { return false; }

    [[nodiscard]] SignatureVerification verify(const std::filesystem::path&,
                                               const CancellationToken&) const override {
        SignatureVerification result;
        result.state = SignatureState::Unavailable;
        result.detail = "Authenticode verification is only available on Windows; the "
                        "certificate table was inspected structurally only";
        return result;
    }
};

} // namespace

std::unique_ptr<ISignatureVerifier> createPlatformSignatureVerifier() {
    return std::make_unique<UnsupportedSignatureVerifier>();
}

} // namespace sectoryn

#endif
