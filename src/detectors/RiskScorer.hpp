#pragma once

#include "core/Result.hpp"
#include "detectors/Finding.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {

// Triage outcomes, not verdicts. None of them claims a file is malicious or safe.
enum class TriageOutcome : std::uint8_t {
    NoSignificantIndicators,
    SuspiciousIndicators,
    HighPriority,
    AnalysisIncomplete,
    UnsupportedOrInvalid,
};

[[nodiscard]] std::string_view toString(TriageOutcome outcome) noexcept;

struct ScoringPolicy {
    // Points per finding by severity (Informational..Critical) before confidence is applied.
    std::array<double, 5> severityPoints = {0.0, 5.0, 15.0, 30.0, 50.0};
    // Multipliers by confidence (Low, Medium, High).
    std::array<double, 3> confidenceFactors = {0.5, 0.75, 1.0};
    double suspiciousThreshold = 20.0;
    double highPriorityThreshold = 50.0;
};

[[nodiscard]] Status validate(const ScoringPolicy& policy);

struct ScoreContribution {
    std::size_t findingIndex = 0;
    std::string ruleId;
    double points = 0.0;
    bool counted = false;
    // For findings that were not counted, the rule ID that represented their group.
    std::string correlatedWith;
};

struct RiskAssessment {
    TriageOutcome outcome = TriageOutcome::AnalysisIncomplete;
    double score = 0.0;
    std::vector<ScoreContribution> contributions;
    // Parts of the analysis that did not complete. Their absence must not read as "clean".
    std::vector<std::string> coverageGaps;
    std::string explanation;

    static constexpr double kMaxScore = 100.0;
};

// Scores findings additively, counting only the strongest finding of each correlation group
// so that several views of the same behavior do not inflate the score. The score ranks files for
// attention; it is not a probability of maliciousness.
[[nodiscard]] RiskAssessment assessRisk(const std::vector<Finding>& findings,
                                        std::vector<std::string> coverageGaps,
                                        const ScoringPolicy& policy = {});

[[nodiscard]] RiskAssessment unsupportedFile(std::string reason);

} // namespace sectoryn
