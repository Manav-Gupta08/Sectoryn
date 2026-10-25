#include "detectors/RuleRegistry.hpp"

#include <algorithm>
#include <exception>
#include <format>
#include <iterator>
#include <utility>

namespace sectoryn {

Status RuleRegistry::add(std::unique_ptr<IRule> rule) {
    if (!rule) {
        return Error{ErrorCode::InvalidInput, "rule is null"};
    }
    const std::string_view id = rule->id();
    if (id.empty()) {
        return Error{ErrorCode::InvalidInput, "rule has an empty identifier"};
    }
    const bool duplicate = std::ranges::any_of(rules_, [id](const auto& existing) {
        return existing->id() == id;
    });
    if (duplicate) {
        return Error{ErrorCode::InvalidInput, std::format("rule '{}' is already registered", id)};
    }
    rules_.push_back(std::move(rule));
    return {};
}

Result<RuleEvaluation> RuleRegistry::evaluate(const RuleContext& context,
                                              const CancellationToken& token) const {
    RuleEvaluation evaluation;
    for (const std::unique_ptr<const IRule>& rule : rules_) {
        if (Status status = checkCancelled(token); !status) {
            return std::move(status).error();
        }

        std::vector<Finding> findings;
        try {
            const RuleOutcome outcome = rule->evaluate(context, findings);
            if (!outcome.evaluated) {
                evaluation.skipped.push_back({std::string(rule->id()), outcome.skipReason});
            }
        } catch (const std::exception& e) {
            evaluation.failed.push_back({std::string(rule->id()), e.what()});
            continue;
        }
        std::ranges::move(findings, std::back_inserter(evaluation.findings));
    }
    return evaluation;
}

} // namespace sectoryn
