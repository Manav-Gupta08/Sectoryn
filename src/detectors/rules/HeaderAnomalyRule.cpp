#include "detectors/rules/HeaderAnomalyRule.hpp"

#include "detectors/rules/RuleSupport.hpp"

#include <algorithm>
#include <array>
#include <format>
#include <string_view>

namespace sectoryn::rules {

namespace {

constexpr std::array<std::string_view, 2> kEntryPointIssues = {
    "header.entry_point_outside_sections",
    "header.entry_point_in_headers",
};

bool isEntryPointIssue(const StructuralIssue& issue) {
    return std::ranges::find(kEntryPointIssues, issue.code) != kEntryPointIssues.end();
}

Evidence issueEvidence(const StructuralIssue& issue) {
    return {.description = issue.message, .fileOffset = std::nullopt, .location = issue.code};
}

} // namespace

RuleOutcome HeaderAnomalyRule::evaluate(const RuleContext& context,
                                        std::vector<Finding>& findings) const {
    Finding entryPoint{
        .ruleId = "header.entry_point_unusual",
        .title = "Entry point outside the code sections",
        .description = "Execution would start somewhere other than a section of the image.",
        .severity = Severity::Medium,
        .confidence = Confidence::Medium,
        .explanation = "Compilers place the entry point inside a code section. Starting in the "
                       "headers or in unmapped space is typical of packers and hand-made files.",
        .limitations = "A few legitimate tiny executables and some protectors do this as well.",
        .attack = {},
        .nextStep = "Disassemble the bytes at the entry point to see what runs first.",
        .correlationGroup = "packing",
    };
    Finding inconsistent{
        .ruleId = "header.inconsistent",
        .title = "Inconsistent PE headers",
        .description = "Header fields contradict each other or the size of the file.",
        .severity = Severity::Low,
        .confidence = Confidence::High,
        .explanation = "Files built by standard toolchains have consistent headers. "
                       "Inconsistencies point to tampering, corruption or a crafted file.",
        .limitations = "The Windows loader ignores many header fields, so an inconsistency "
                       "does not mean the file fails to run, and corruption can be accidental.",
        .attack = {},
        .nextStep = "Review the listed fields and check whether the file is complete.",
        .correlationGroup = "malformed",
    };

    std::size_t otherIssues = 0;
    for (const StructuralIssue& issue : context.image.issues) {
        if (isEntryPointIssue(issue)) {
            addEvidence(entryPoint, issueEvidence(issue));
        } else {
            ++otherIssues;
            addEvidence(inconsistent, issueEvidence(issue));
        }
    }

    if (!entryPoint.evidence.empty()) {
        findings.push_back(std::move(entryPoint));
    }
    if (otherIssues > 0) {
        if (otherIssues > inconsistent.evidence.size()) {
            inconsistent.description += std::format(" {} issues in total; the first {} are listed.",
                                                    otherIssues, inconsistent.evidence.size());
        }
        findings.push_back(std::move(inconsistent));
    }
    return RuleOutcome::ran();
}

} // namespace sectoryn::rules
