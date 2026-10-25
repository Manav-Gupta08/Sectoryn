#pragma once

#include "analysis/SectionAnalyzer.hpp"
#include "detectors/Finding.hpp"
#include "detectors/IRule.hpp"
#include "parsers/PeModel.hpp"

#include <cstddef>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn::rules {

// Evidence pointing at a section, with its raw offset when the section has data in the file.
[[nodiscard]] Evidence sectionEvidence(const PeImage& image, std::size_t index,
                                       std::string description);

// Appends evidence unless the finding already holds Finding::kMaxEvidence items.
void addEvidence(Finding& finding, Evidence evidence);

// Collects every section anomaly of the given kinds into `prototype` and appends it to
// `findings`. Nothing is appended when no such anomaly exists.
void reportAnomalies(const RuleContext& context, std::initializer_list<SectionAnomalyKind> kinds,
                     Finding prototype, std::vector<Finding>& findings);

// "1 section" / "3 sections".
[[nodiscard]] std::string countNoun(std::size_t count, std::string_view singular,
                                    std::string_view plural);

} // namespace sectoryn::rules
