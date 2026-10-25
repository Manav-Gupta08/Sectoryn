#pragma once

#include "detectors/IRule.hpp"

namespace sectoryn::rules {

// Checks where the certificate table sits. It does not verify the signature; that is done by
// the platform's Authenticode verifier where one exists.
class SignatureRule final : public IRule {
public:
    [[nodiscard]] std::string_view id() const noexcept override { return "signature.layout"; }
    [[nodiscard]] std::string_view summary() const noexcept override {
        return "Flags certificate tables that do not end the file or lie inside image data.";
    }

    [[nodiscard]] RuleOutcome evaluate(const RuleContext& context,
                                       std::vector<Finding>& findings) const override;
};

} // namespace sectoryn::rules
