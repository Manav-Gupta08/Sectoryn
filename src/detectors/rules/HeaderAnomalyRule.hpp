#pragma once

#include "detectors/IRule.hpp"

namespace sectoryn::rules {

// Turns the parser's structural issues into findings.
class HeaderAnomalyRule final : public IRule {
public:
    [[nodiscard]] std::string_view id() const noexcept override { return "header.structure"; }
    [[nodiscard]] std::string_view summary() const noexcept override {
        return "Flags inconsistent PE headers and entry points outside the code sections.";
    }

    [[nodiscard]] RuleOutcome evaluate(const RuleContext& context,
                                       std::vector<Finding>& findings) const override;
};

} // namespace sectoryn::rules
