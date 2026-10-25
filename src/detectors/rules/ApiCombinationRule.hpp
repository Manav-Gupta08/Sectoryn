#pragma once

#include "detectors/ApiCatalogue.hpp"
#include "detectors/IRule.hpp"

namespace sectoryn::rules {

// Infers capabilities from combinations of imported functions. A single import says little; the
// catalogue only reports a capability when every category it requires is present.
class ApiCombinationRule final : public IRule {
public:
    explicit ApiCombinationRule(ApiCatalogue catalogue);

    [[nodiscard]] std::string_view id() const noexcept override { return "api"; }
    [[nodiscard]] std::string_view summary() const noexcept override {
        return "Reports capabilities implied by combinations of imported functions.";
    }

    [[nodiscard]] RuleOutcome evaluate(const RuleContext& context,
                                       std::vector<Finding>& findings) const override;

private:
    ApiCatalogue catalogue_;
};

} // namespace sectoryn::rules
