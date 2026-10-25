#include "detectors/DefaultRules.hpp"

#include "detectors/rules/ApiCombinationRule.hpp"
#include "detectors/rules/EntropyRule.hpp"
#include "detectors/rules/HeaderAnomalyRule.hpp"
#include "detectors/rules/SectionAnomalyRule.hpp"
#include "detectors/rules/SectionPermissionRule.hpp"
#include "detectors/rules/SignatureRule.hpp"
#include "detectors/rules/StringIndicatorRule.hpp"

#include <memory>
#include <utility>

namespace sectoryn {

Result<RuleRegistry> createDefaultRules(ApiCatalogue catalogue) {
    RuleRegistry registry;
    std::unique_ptr<IRule> rules[] = {
        std::make_unique<rules::HeaderAnomalyRule>(),
        std::make_unique<rules::SectionPermissionRule>(),
        std::make_unique<rules::SectionAnomalyRule>(),
        std::make_unique<rules::EntropyRule>(),
        std::make_unique<rules::ApiCombinationRule>(std::move(catalogue)),
        std::make_unique<rules::StringIndicatorRule>(),
        std::make_unique<rules::SignatureRule>(),
    };
    for (std::unique_ptr<IRule>& rule : rules) {
        if (Status added = registry.add(std::move(rule)); !added) {
            return std::move(added).error();
        }
    }
    return registry;
}

} // namespace sectoryn
