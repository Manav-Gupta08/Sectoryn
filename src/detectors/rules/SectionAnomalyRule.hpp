#pragma once

#include "detectors/IRule.hpp"

namespace sectoryn::rules {

// Section layouts that standard linkers do not produce: overlaps, data outside the file,
// misalignment, packer section names and unusual names.
class SectionAnomalyRule final : public IRule {
public:
    [[nodiscard]] std::string_view id() const noexcept override { return "section.layout"; }
    [[nodiscard]] std::string_view summary() const noexcept override {
        return "Flags overlapping, misaligned or truncated sections and section names used by "
               "packers.";
    }

    [[nodiscard]] RuleOutcome evaluate(const RuleContext& context,
                                       std::vector<Finding>& findings) const override;
};

} // namespace sectoryn::rules
