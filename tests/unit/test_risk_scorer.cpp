#include "detectors/RiskScorer.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace sectoryn {
namespace {

Finding finding(std::string id, Severity severity, Confidence confidence,
                std::string group = {}) {
    return {.ruleId = std::move(id),
            .severity = severity,
            .confidence = confidence,
            .correlationGroup = std::move(group)};
}

TEST(RiskScorer, NoFindingsAndFullCoverage) {
    const RiskAssessment risk = assessRisk({}, {});
    EXPECT_EQ(risk.score, 0.0);
    EXPECT_EQ(risk.outcome, TriageOutcome::NoSignificantIndicators);
    EXPECT_NE(risk.explanation.find("not a probability"), std::string::npos);
}

TEST(RiskScorer, MissingCoverageIsNeverReportedAsClean) {
    const RiskAssessment risk = assessRisk({}, {"imports: parser error"});
    EXPECT_EQ(risk.outcome, TriageOutcome::AnalysisIncomplete);
    EXPECT_EQ(risk.coverageGaps.size(), 1U);
    EXPECT_NE(risk.explanation.find("did not complete"), std::string::npos);
}

TEST(RiskScorer, WeighsSeverityByConfidence) {
    // Default policy: Medium = 15 points, High confidence x1.0, Low confidence x0.5.
    EXPECT_DOUBLE_EQ(assessRisk({finding("a", Severity::Medium, Confidence::High)}, {}).score,
                     15.0);
    EXPECT_DOUBLE_EQ(assessRisk({finding("a", Severity::Medium, Confidence::Low)}, {}).score, 7.5);
    EXPECT_DOUBLE_EQ(
        assessRisk({finding("a", Severity::Informational, Confidence::High)}, {}).score, 0.0);
}

TEST(RiskScorer, AppliesThresholds) {
    const auto outcomeFor = [](const std::vector<Finding>& findings) {
        return assessRisk(findings, {}).outcome;
    };
    EXPECT_EQ(outcomeFor({finding("a", Severity::Low, Confidence::High)}),
              TriageOutcome::NoSignificantIndicators);
    EXPECT_EQ(outcomeFor({finding("a", Severity::High, Confidence::Medium)}),
              TriageOutcome::SuspiciousIndicators);
    EXPECT_EQ(outcomeFor({finding("a", Severity::Critical, Confidence::High)}),
              TriageOutcome::HighPriority);
}

TEST(RiskScorer, HighScoreWinsOverIncompleteCoverage) {
    const RiskAssessment risk =
        assessRisk({finding("a", Severity::Critical, Confidence::High)}, {"strings: limit"});
    EXPECT_EQ(risk.outcome, TriageOutcome::HighPriority);
}

TEST(RiskScorer, CountsCorrelatedFindingsOnce) {
    const std::vector<Finding> findings = {
        finding("section.writable_executable", Severity::Medium, Confidence::High, "packing"),
        finding("entropy.packed_code", Severity::Medium, Confidence::Medium, "packing"),
        finding("section.packer_name", Severity::Medium, Confidence::High, "packing"),
        finding("api.process_injection", Severity::High, Confidence::Medium, "injection"),
    };
    const RiskAssessment risk = assessRisk(findings, {});
    EXPECT_DOUBLE_EQ(risk.score, 15.0 + 22.5);
    ASSERT_EQ(risk.contributions.size(), 4U);
    EXPECT_TRUE(risk.contributions[0].counted);
    EXPECT_FALSE(risk.contributions[1].counted);
    // Equal points: the earlier finding represents the group.
    EXPECT_FALSE(risk.contributions[2].counted);
    EXPECT_EQ(risk.contributions[2].correlatedWith, "section.writable_executable");
    EXPECT_TRUE(risk.contributions[3].counted);
}

TEST(RiskScorer, CapsScore) {
    std::vector<Finding> findings;
    for (int i = 0; i < 10; ++i) {
        findings.push_back(finding("f" + std::to_string(i), Severity::Critical, Confidence::High));
    }
    EXPECT_EQ(assessRisk(findings, {}).score, RiskAssessment::kMaxScore);
}

TEST(RiskScorer, IsDeterministic) {
    const std::vector<Finding> findings = {
        finding("b", Severity::Medium, Confidence::Medium, "g"),
        finding("a", Severity::Medium, Confidence::Medium, "g"),
        finding("c", Severity::Low, Confidence::High),
    };
    const RiskAssessment first = assessRisk(findings, {});
    const RiskAssessment second = assessRisk(findings, {});
    EXPECT_EQ(first.score, second.score);
    EXPECT_EQ(first.explanation, second.explanation);
    EXPECT_EQ(first.contributions[1].correlatedWith, "b");
}

TEST(RiskScorer, ValidatesPolicy) {
    EXPECT_TRUE(validate(ScoringPolicy{}).hasValue());

    ScoringPolicy inverted;
    inverted.suspiciousThreshold = 60;
    EXPECT_FALSE(validate(inverted).hasValue());

    ScoringPolicy negative;
    negative.severityPoints[2] = -1;
    EXPECT_FALSE(validate(negative).hasValue());
}

TEST(RiskScorer, UnsupportedFile) {
    const RiskAssessment risk = unsupportedFile("ELF signature");
    EXPECT_EQ(risk.outcome, TriageOutcome::UnsupportedOrInvalid);
    EXPECT_EQ(risk.explanation, "ELF signature");
}

TEST(TriageOutcome, NamesDoNotClaimVerdicts) {
    for (const TriageOutcome outcome :
         {TriageOutcome::NoSignificantIndicators, TriageOutcome::SuspiciousIndicators,
          TriageOutcome::HighPriority, TriageOutcome::AnalysisIncomplete,
          TriageOutcome::UnsupportedOrInvalid}) {
        const std::string name(toString(outcome));
        EXPECT_EQ(name.find("safe"), std::string::npos);
        EXPECT_EQ(name.find("clean"), std::string::npos);
        EXPECT_EQ(name.find("malicious"), std::string::npos);
    }
}

} // namespace
} // namespace sectoryn
