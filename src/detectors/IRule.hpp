#pragma once

#include "analysis/EntropyAnalyzer.hpp"
#include "analysis/IndicatorClassifier.hpp"
#include "analysis/SectionAnalyzer.hpp"
#include "analysis/StringExtractor.hpp"
#include "detectors/Finding.hpp"
#include "parsers/PeModel.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sectoryn {

// Everything a rule may look at. Optional inputs are null when that analysis did not run or
// failed; a rule that needs a missing input must report itself as skipped.
struct RuleContext {
    const PeImage& image;
    const SectionAnalysis& sections;
    const EntropyReport* entropy = nullptr;
    const StringExtraction* strings = nullptr;
    const std::vector<Indicator>* indicators = nullptr;
};

struct RuleOutcome {
    bool evaluated = true;
    // Why the rule could not run, e.g. "imports could not be read".
    std::string skipReason;

    [[nodiscard]] static RuleOutcome ran() { return {}; }
    [[nodiscard]] static RuleOutcome skipped(std::string reason) {
        return {false, std::move(reason)};
    }
};

// A rule inspects the context and appends findings. Rules must be deterministic: the same
// context always yields the same findings in the same order.
class IRule {
public:
    virtual ~IRule() = default;

    // Identifies the rule family, e.g. "section.permissions". Finding IDs start with it.
    [[nodiscard]] virtual std::string_view id() const noexcept = 0;
    [[nodiscard]] virtual std::string_view summary() const noexcept = 0;

    [[nodiscard]] virtual RuleOutcome evaluate(const RuleContext& context,
                                               std::vector<Finding>& findings) const = 0;

protected:
    IRule() = default;
    IRule(const IRule&) = default;
    IRule& operator=(const IRule&) = default;
    IRule(IRule&&) = default;
    IRule& operator=(IRule&&) = default;
};

} // namespace sectoryn
