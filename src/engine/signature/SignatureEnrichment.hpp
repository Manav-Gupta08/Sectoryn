#pragma once

#include "engine/Enrichment.hpp"
#include "platform/ISignatureVerifier.hpp"

#include <memory>
#include <string_view>

namespace sectoryn {

// Verifies the Authenticode signature of each analyzed file. A broken signature becomes a
// finding; a missing or valid one does not, since neither says anything about intent.
class SignatureEnrichment final : public IEnrichment {
public:
    explicit SignatureEnrichment(std::shared_ptr<const ISignatureVerifier> verifier);

    [[nodiscard]] std::string_view id() const noexcept override { return "signature"; }
    [[nodiscard]] std::string_view displayName() const noexcept override {
        return "Authenticode signature";
    }

    [[nodiscard]] EnrichmentResult run(const EnrichmentInput& input,
                                       const CancellationToken& token) const override;

private:
    std::shared_ptr<const ISignatureVerifier> verifier_;
};

// The enrichment result for a verification; separate so it can be tested without a platform.
[[nodiscard]] EnrichmentResult signatureResult(const SignatureVerification& verification,
                                               std::string_view verifierName);

} // namespace sectoryn
