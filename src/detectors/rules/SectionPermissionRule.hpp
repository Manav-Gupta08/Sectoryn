#pragma once

#include "detectors/IRule.hpp"

namespace sectoryn::rules {

// Sections whose permissions allow self-modifying code or cross-process sharing.
class SectionPermissionRule final : public IRule {
public:
    [[nodiscard]] std::string_view id() const noexcept override { return "section.permissions"; }
    [[nodiscard]] std::string_view summary() const noexcept override {
        return "Flags sections that are writable and executable, executable without being "
               "marked as code, or shared and writable.";
    }

    [[nodiscard]] RuleOutcome evaluate(const RuleContext& context,
                                       std::vector<Finding>& findings) const override;
};

} // namespace sectoryn::rules
