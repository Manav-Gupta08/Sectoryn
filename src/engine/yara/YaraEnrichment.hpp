#pragma once

#include "detectors/yara/YaraCompiler.hpp"
#include "detectors/yara/YaraScanner.hpp"
#include "engine/Enrichment.hpp"

#include <memory>
#include <string_view>

namespace sectoryn {

// Scans each analyzed file with the user's YARA rules and turns every matching rule into a
// finding. All YARA findings share one correlation group, so a large rule set cannot inflate the
// score by matching many times.
class YaraEnrichment final : public IEnrichment {
public:
    explicit YaraEnrichment(std::shared_ptr<const YaraRuleSet> rules,
                            YaraScanOptions options = {});

    [[nodiscard]] std::string_view id() const noexcept override { return "yara"; }
    [[nodiscard]] std::string_view displayName() const noexcept override { return "YARA rules"; }

    [[nodiscard]] EnrichmentResult run(const EnrichmentInput& input,
                                       const CancellationToken& token) const override;

private:
    std::shared_ptr<const YaraRuleSet> rules_;
    YaraScanOptions options_;
};

// The finding reported for one matching rule.
[[nodiscard]] Finding findingForYaraMatch(const YaraMatch& match);

} // namespace sectoryn
