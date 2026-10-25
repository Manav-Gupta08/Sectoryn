#pragma once

#include "detectors/IRule.hpp"

#include <cstdint>

namespace sectoryn::rules {

// High entropy in executable sections, other sections and the overlay.
class EntropyRule final : public IRule {
public:
    // Compiled code rarely exceeds about 6.8 bits per byte; compressed data sits near 8.
    static constexpr double kHighEntropy = 7.2;
    // Entropy estimates over short ranges are noisy and biased low, so they are not judged.
    static constexpr std::uint64_t kMinBytes = 1024;

    [[nodiscard]] std::string_view id() const noexcept override { return "entropy"; }
    [[nodiscard]] std::string_view summary() const noexcept override {
        return "Flags sections and overlays whose entropy suggests compressed or encrypted "
               "content.";
    }

    [[nodiscard]] RuleOutcome evaluate(const RuleContext& context,
                                       std::vector<Finding>& findings) const override;
};

} // namespace sectoryn::rules
