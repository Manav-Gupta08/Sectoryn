#pragma once

#include "core/CancellationToken.hpp"
#include "core/Limits.hpp"
#include "core/Result.hpp"
#include "detectors/RiskScorer.hpp"
#include "detectors/RuleRegistry.hpp"
#include "engine/AnalysisResult.hpp"
#include "engine/Enrichment.hpp"
#include "parsers/IPeParser.hpp"

#include <filesystem>
#include <functional>
#include <memory>
#include <vector>

namespace sectoryn {

struct EngineOptions {
    AnalysisLimits limits;
    ScoringPolicy scoring;
};

// Runs the complete static analysis of one file: intake, hashing, identification, PE parsing,
// section, string and entropy analysis, optional enrichments, rules and scoring. The analyzed
// file is only ever read; it is never executed or loaded as a library.
//
// analyze() is const and keeps no per-file state, so one engine can serve several worker
// threads as long as its rules and enrichments are thread-safe (the built-in ones are).
class AnalysisEngine {
public:
    using ProgressCallback = std::function<void(AnalysisStage)>;

    // Fails if the options are invalid or no parser is given.
    [[nodiscard]] static Result<AnalysisEngine>
    create(EngineOptions options, std::unique_ptr<IPeParser> parser, RuleRegistry rules,
           std::vector<std::shared_ptr<const IEnrichment>> enrichments = {});

    // LIEF parser and the built-in rules and catalogue, plus any optional enrichments.
    [[nodiscard]] static Result<AnalysisEngine>
    createDefault(EngineOptions options = {},
                  std::vector<std::shared_ptr<const IEnrichment>> enrichments = {});

    // Errors are returned only when there is nothing useful to report: the file cannot be
    // opened or read, a limit forbids analyzing it, or the analysis was cancelled. Files that
    // are not PE or cannot be parsed yield a result whose outcome says so.
    [[nodiscard]] Result<AnalysisResult> analyze(const std::filesystem::path& path,
                                                 const CancellationToken& token = {},
                                                 const ProgressCallback& progress = {}) const;

    [[nodiscard]] const EngineOptions& options() const noexcept { return options_; }

private:
    AnalysisEngine(EngineOptions options, std::unique_ptr<IPeParser> parser, RuleRegistry rules,
                   std::vector<std::shared_ptr<const IEnrichment>> enrichments);

    [[nodiscard]] Result<AnalysisResult> run(const std::filesystem::path& path,
                                             const CancellationToken& token,
                                             const ProgressCallback& progress) const;

    EngineOptions options_;
    std::unique_ptr<IPeParser> parser_;
    RuleRegistry rules_;
    std::vector<std::shared_ptr<const IEnrichment>> enrichments_;
};

} // namespace sectoryn
