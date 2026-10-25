#pragma once

#include "analysis/EntropyAnalyzer.hpp"
#include "analysis/FileIdentifier.hpp"
#include "analysis/FileIntake.hpp"
#include "analysis/IndicatorClassifier.hpp"
#include "analysis/SectionAnalyzer.hpp"
#include "analysis/StringExtractor.hpp"
#include "detectors/Finding.hpp"
#include "detectors/RiskScorer.hpp"
#include "detectors/RuleRegistry.hpp"
#include "engine/Enrichment.hpp"
#include "parsers/PeModel.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {

enum class AnalysisStage : std::uint8_t {
    Opening,
    Hashing,
    Identifying,
    Parsing,
    Sections,
    Strings,
    Entropy,
    Enrichment,
    Rules,
    Scoring,
};

[[nodiscard]] std::string_view toString(AnalysisStage stage) noexcept;

struct EngineInfo {
    std::string version;
    std::string parserName;
    std::string parserVersion;
};

// Wall-clock details that differ between runs. Kept apart from the reproducible results.
struct RunInfo {
    std::chrono::system_clock::time_point started;
    std::chrono::system_clock::time_point finished;
};

struct AnalysisResult {
    FileMetadata file;
    std::string sha256;
    FileIdentification identification;

    // Present only for files that parsed as PE.
    std::optional<PeImage> pe;
    SectionAnalysis sections;
    std::optional<EntropyReport> entropy;
    std::optional<StringExtraction> strings;
    std::vector<Indicator> indicators;
    std::vector<EnrichmentResult> enrichments;

    std::vector<Finding> findings;
    std::vector<RuleSkip> skippedRules;
    std::vector<RuleSkip> failedRules;
    RiskAssessment risk;

    // Problems that did not stop the analysis, e.g. a stage that failed on this file.
    std::vector<std::string> warnings;

    EngineInfo engine;
    RunInfo run;
};

} // namespace sectoryn
