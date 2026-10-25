#pragma once

#include "core/CancellationToken.hpp"
#include "core/Result.hpp"
#include "detectors/IRule.hpp"

#include <memory>
#include <string>
#include <vector>

namespace sectoryn {

struct RuleSkip {
    std::string ruleId;
    std::string reason;
};

struct RuleEvaluation {
    std::vector<Finding> findings;
    std::vector<RuleSkip> skipped;
    // Rules that threw. Their partial findings are discarded.
    std::vector<RuleSkip> failed;
};

class RuleRegistry {
public:
    [[nodiscard]] Status add(std::unique_ptr<IRule> rule);

    [[nodiscard]] std::size_t size() const noexcept { return rules_.size(); }
    [[nodiscard]] const IRule& at(std::size_t index) const { return *rules_.at(index); }

    // Runs every rule in registration order. A rule that throws is recorded as failed and does
    // not stop the others.
    [[nodiscard]] Result<RuleEvaluation> evaluate(const RuleContext& context,
                                                  const CancellationToken& token) const;

private:
    std::vector<std::unique_ptr<const IRule>> rules_;
};

} // namespace sectoryn
