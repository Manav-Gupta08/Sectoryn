#pragma once

#include "detectors/IRule.hpp"

namespace sectoryn::rules {

// Turns string indicators (URLs, command lines, persistence references, ...) into findings.
class StringIndicatorRule final : public IRule {
public:
    [[nodiscard]] std::string_view id() const noexcept override { return "strings"; }
    [[nodiscard]] std::string_view summary() const noexcept override {
        return "Reports network indicators, script and command fragments, persistence "
               "references and encoded data found in the file's strings.";
    }

    [[nodiscard]] RuleOutcome evaluate(const RuleContext& context,
                                       std::vector<Finding>& findings) const override;
};

} // namespace sectoryn::rules
