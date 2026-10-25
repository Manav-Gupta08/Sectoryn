#include "detectors/rules/RuleSupport.hpp"

#include <algorithm>
#include <format>
#include <utility>

namespace sectoryn::rules {

Evidence sectionEvidence(const PeImage& image, std::size_t index, std::string description) {
    Evidence evidence;
    evidence.description = std::move(description);
    if (index < image.sections.size()) {
        const Section& section = image.sections[index];
        evidence.location = std::format("section {} '{}'", index, section.name);
        if (section.sizeOfRawData != 0 && section.pointerToRawData < image.fileSize) {
            evidence.fileOffset = section.pointerToRawData;
        }
    }
    return evidence;
}

void addEvidence(Finding& finding, Evidence evidence) {
    if (finding.evidence.size() < Finding::kMaxEvidence) {
        finding.evidence.push_back(std::move(evidence));
    }
}

void reportAnomalies(const RuleContext& context, std::initializer_list<SectionAnomalyKind> kinds,
                     Finding prototype, std::vector<Finding>& findings) {
    std::size_t matches = 0;
    for (const SectionAnomaly& anomaly : context.sections.anomalies) {
        if (std::ranges::find(kinds, anomaly.kind) == kinds.end()) {
            continue;
        }
        ++matches;
        addEvidence(prototype,
                    sectionEvidence(context.image, anomaly.section, anomaly.description));
    }
    if (matches == 0) {
        return;
    }
    if (matches > prototype.evidence.size()) {
        prototype.description +=
            std::format(" {} occurrences in total; the first {} are listed.", matches,
                        prototype.evidence.size());
    }
    findings.push_back(std::move(prototype));
}

std::string countNoun(std::size_t count, std::string_view singular, std::string_view plural) {
    return std::format("{} {}", count, count == 1 ? singular : plural);
}

} // namespace sectoryn::rules
