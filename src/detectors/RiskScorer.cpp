#include "detectors/RiskScorer.hpp"

#include <algorithm>
#include <format>
#include <map>
#include <numeric>
#include <utility>

namespace sectoryn {

std::string_view toString(TriageOutcome outcome) noexcept {
    switch (outcome) {
    case TriageOutcome::NoSignificantIndicators:
        return "No significant indicators detected";
    case TriageOutcome::SuspiciousIndicators:
        return "Suspicious indicators detected";
    case TriageOutcome::HighPriority:
        return "High-priority investigation recommended";
    case TriageOutcome::AnalysisIncomplete:
        return "Analysis incomplete";
    case TriageOutcome::UnsupportedOrInvalid:
        return "Unsupported or invalid file";
    }
    return "unknown";
}

Status validate(const ScoringPolicy& policy) {
    const auto negative = [](double value) { return value < 0.0; };
    if (std::ranges::any_of(policy.severityPoints, negative) ||
        std::ranges::any_of(policy.confidenceFactors, negative)) {
        return Error{ErrorCode::InvalidInput, "scoring weights must not be negative"};
    }
    // Written as a negation so that NaN thresholds are rejected too.
    if (!(policy.suspiciousThreshold > 0.0 && // NOLINT(readability-simplify-boolean-expr)
          policy.suspiciousThreshold < policy.highPriorityThreshold &&
          policy.highPriorityThreshold <= RiskAssessment::kMaxScore)) {
        return Error{ErrorCode::InvalidInput,
                     std::format("thresholds must satisfy 0 < suspicious < high priority <= {}",
                                 RiskAssessment::kMaxScore)};
    }
    return {};
}

RiskAssessment assessRisk(const std::vector<Finding>& findings,
                          std::vector<std::string> coverageGaps, const ScoringPolicy& policy) {
    RiskAssessment assessment;
    assessment.coverageGaps = std::move(coverageGaps);

    assessment.contributions.reserve(findings.size());
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const Finding& finding = findings[i];
        const double points =
            policy.severityPoints[static_cast<std::size_t>(finding.severity)] *
            policy.confidenceFactors[static_cast<std::size_t>(finding.confidence)];
        assessment.contributions.push_back({i, finding.ruleId, points, true, {}});
    }

    // Within a group only the highest-scoring finding counts; ties go to the earlier finding.
    std::map<std::string, std::size_t> representative;
    for (ScoreContribution& contribution : assessment.contributions) {
        const std::string& group = findings[contribution.findingIndex].correlationGroup;
        if (group.empty()) {
            continue;
        }
        const auto [it, inserted] = representative.try_emplace(group, contribution.findingIndex);
        if (!inserted && contribution.points > assessment.contributions[it->second].points) {
            it->second = contribution.findingIndex;
        }
    }
    for (ScoreContribution& contribution : assessment.contributions) {
        const std::string& group = findings[contribution.findingIndex].correlationGroup;
        if (const auto it = representative.find(group);
            it != representative.end() && it->second != contribution.findingIndex) {
            contribution.counted = false;
            contribution.correlatedWith = findings[it->second].ruleId;
        }
    }

    const double total = std::accumulate(
        assessment.contributions.begin(), assessment.contributions.end(), 0.0,
        [](double sum, const ScoreContribution& c) { return c.counted ? sum + c.points : sum; });
    assessment.score = std::min(total, RiskAssessment::kMaxScore);

    const bool incomplete = !assessment.coverageGaps.empty();
    if (assessment.score >= policy.highPriorityThreshold) {
        assessment.outcome = TriageOutcome::HighPriority;
    } else if (assessment.score >= policy.suspiciousThreshold) {
        assessment.outcome = TriageOutcome::SuspiciousIndicators;
    } else if (incomplete) {
        assessment.outcome = TriageOutcome::AnalysisIncomplete;
    } else {
        assessment.outcome = TriageOutcome::NoSignificantIndicators;
    }

    const auto counted = static_cast<std::size_t>(std::ranges::count_if(
        assessment.contributions, [](const ScoreContribution& c) { return c.counted; }));
    assessment.explanation = std::format(
        "Score {:.1f} of {:.0f} from {} counted finding(s); {} correlated finding(s) were not "
        "counted again. Thresholds: {:.0f} for suspicious, {:.0f} for high priority. The score "
        "ranks files for attention and is not a probability that the file is malicious.",
        assessment.score, RiskAssessment::kMaxScore, counted, findings.size() - counted,
        policy.suspiciousThreshold, policy.highPriorityThreshold);
    if (incomplete) {
        assessment.explanation += std::format(
            " {} part(s) of the analysis did not complete, so a low score does not mean the file "
            "has no indicators.",
            assessment.coverageGaps.size());
    }
    return assessment;
}

RiskAssessment unsupportedFile(std::string reason) {
    RiskAssessment assessment;
    assessment.outcome = TriageOutcome::UnsupportedOrInvalid;
    assessment.explanation = std::move(reason);
    return assessment;
}

} // namespace sectoryn
