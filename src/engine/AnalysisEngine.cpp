#include "engine/AnalysisEngine.hpp"

#include "detectors/ApiCatalogue.hpp"
#include "detectors/DefaultRules.hpp"
#include "parsers/LiefPeParser.hpp"
#include "utilities/FileReader.hpp"
#include "utilities/Sha256.hpp"

#include <exception>
#include <format>
#include <new>
#include <utility>

#ifndef SECTORYN_VERSION
#error "SECTORYN_VERSION must be defined by the build system"
#endif

namespace sectoryn {

namespace {

bool isGap(const FieldStatus& status) {
    switch (status.state) {
    case FieldState::Present:
    case FieldState::Absent:
        return false;
    case FieldState::NotInspected:
    case FieldState::Invalid:
    case FieldState::Unsupported:
    case FieldState::ParserError:
    case FieldState::Incomplete:
        return true;
    }
    return true;
}

void addGap(std::vector<std::string>& gaps, std::string_view what, const FieldStatus& status) {
    if (isGap(status)) {
        gaps.push_back(std::format("{}: {}{}{}", what, toString(status.state),
                                   status.detail.empty() ? "" : " - ", status.detail));
    }
}

std::vector<std::string> coverageGaps(const AnalysisResult& result) {
    std::vector<std::string> gaps;
    const PeImage& pe = *result.pe;
    addGap(gaps, "section table", pe.sectionTable);
    addGap(gaps, "imports", pe.imports.status);
    addGap(gaps, "delay imports", pe.imports.delayStatus);
    addGap(gaps, "exports", pe.exports.status);
    addGap(gaps, "resources", pe.resources.status);
    addGap(gaps, "debug directory", pe.debug.status);
    addGap(gaps, "TLS directory", pe.tls.status);
    addGap(gaps, "certificate table", pe.certificate.status);
    addGap(gaps, "overlay", pe.overlay.status);

    if (!result.strings) {
        gaps.emplace_back("strings: not extracted");
    } else if (result.strings->limitReached) {
        gaps.emplace_back("strings: extraction stopped at a configured limit");
    }
    if (!result.entropy) {
        gaps.emplace_back("entropy: not computed");
    } else if (result.entropy->sectionBudgetExhausted) {
        gaps.emplace_back("entropy: some overlapping sections were not measured");
    }
    for (const RuleSkip& skip : result.skippedRules) {
        gaps.push_back(std::format("rule {} skipped: {}", skip.ruleId, skip.reason));
    }
    for (const RuleSkip& failure : result.failedRules) {
        gaps.push_back(std::format("rule {} failed: {}", failure.ruleId, failure.reason));
    }
    for (const EnrichmentResult& enrichment : result.enrichments) {
        addGap(gaps, enrichment.displayName, enrichment.status);
    }
    return gaps;
}

// Strings and entropy are useful but not essential. Losing them is recorded as a warning; only
// cancellation and a file that changes underneath the analysis end the run.
bool endsAnalysis(const Error& error) {
    return error.code == ErrorCode::Cancelled || error.code == ErrorCode::IoFailure;
}

void notify(const AnalysisEngine::ProgressCallback& progress, AnalysisStage stage) {
    if (progress) {
        progress(stage);
    }
}

EnrichmentResult runEnrichment(const IEnrichment& enrichment, const EnrichmentInput& input,
                               const CancellationToken& token) {
    try {
        return enrichment.run(input, token);
    } catch (const std::exception& e) {
        EnrichmentResult failed;
        failed.id = enrichment.id();
        failed.displayName = enrichment.displayName();
        failed.status = FieldStatus::parserError(std::format("module failed: {}", e.what()));
        return failed;
    }
}

} // namespace

std::string_view toString(AnalysisStage stage) noexcept {
    switch (stage) {
    case AnalysisStage::Opening:
        return "Opening file";
    case AnalysisStage::Hashing:
        return "Hashing";
    case AnalysisStage::Identifying:
        return "Identifying format";
    case AnalysisStage::Parsing:
        return "Parsing PE structures";
    case AnalysisStage::Sections:
        return "Analyzing sections";
    case AnalysisStage::Strings:
        return "Extracting strings";
    case AnalysisStage::Entropy:
        return "Measuring entropy";
    case AnalysisStage::Enrichment:
        return "Running optional modules";
    case AnalysisStage::Rules:
        return "Evaluating rules";
    case AnalysisStage::Scoring:
        return "Scoring";
    }
    return "unknown";
}

AnalysisEngine::AnalysisEngine(EngineOptions options, std::unique_ptr<IPeParser> parser,
                               RuleRegistry rules,
                               std::vector<std::shared_ptr<const IEnrichment>> enrichments)
    : options_(options)
    , parser_(std::move(parser))
    , rules_(std::move(rules))
    , enrichments_(std::move(enrichments)) {}

Result<AnalysisEngine> AnalysisEngine::create(
    EngineOptions options, std::unique_ptr<IPeParser> parser, RuleRegistry rules,
    std::vector<std::shared_ptr<const IEnrichment>> enrichments) {
    if (Status status = validate(options.limits); !status) {
        return std::move(status).error();
    }
    if (Status status = validate(options.scoring); !status) {
        return std::move(status).error();
    }
    if (!parser) {
        return Error{ErrorCode::InvalidInput, "no PE parser given"};
    }
    for (const std::shared_ptr<const IEnrichment>& enrichment : enrichments) {
        if (!enrichment) {
            return Error{ErrorCode::InvalidInput, "enrichment is null"};
        }
    }
    return AnalysisEngine(options, std::move(parser), std::move(rules),
                          std::move(enrichments));
}

Result<AnalysisEngine> AnalysisEngine::createDefault(
    EngineOptions options, std::vector<std::shared_ptr<const IEnrichment>> enrichments) {
    Result<ApiCatalogue> catalogue = ApiCatalogue::builtIn();
    if (!catalogue) {
        return std::move(catalogue).error();
    }
    Result<RuleRegistry> rules = createDefaultRules(std::move(catalogue).value());
    if (!rules) {
        return std::move(rules).error();
    }
    return create(options, std::make_unique<LiefPeParser>(),
                  std::move(rules).value(), std::move(enrichments));
}

Result<AnalysisResult> AnalysisEngine::analyze(const std::filesystem::path& path,
                                               const CancellationToken& token,
                                               const ProgressCallback& progress) const {
    try {
        return run(path, token, progress);
    } catch (const std::bad_alloc&) {
        return Error{ErrorCode::ResourceLimitExceeded, "out of memory during analysis"};
    } catch (const std::exception& e) {
        return Error{ErrorCode::Internal, std::format("analysis failed: {}", e.what())};
    }
}

Result<AnalysisResult> AnalysisEngine::run(const std::filesystem::path& path,
                                           const CancellationToken& token,
                                           const ProgressCallback& progress) const {
    const AnalysisLimits& limits = options_.limits;
    AnalysisResult result;
    result.run.started = std::chrono::system_clock::now();
    result.engine = {SECTORYN_VERSION, parser_->name(), parser_->version()};

    notify(progress, AnalysisStage::Opening);
    Result<OpenedFile> opened = openForAnalysis(path, limits);
    if (!opened) {
        return std::move(opened).error();
    }
    result.file = std::move(opened.value().metadata);
    FileReader& reader = opened.value().reader;

    notify(progress, AnalysisStage::Hashing);
    Result<Sha256::Digest> digest = sha256File(reader, limits.readChunkBytes, token);
    if (!digest) {
        return std::move(digest).error();
    }
    result.sha256 = Sha256::toHex(digest.value());

    notify(progress, AnalysisStage::Identifying);
    Result<FileIdentification> identification = identifyFile(reader);
    if (!identification) {
        return std::move(identification).error();
    }
    result.identification = std::move(identification).value();
    if (result.identification.kind != FileKind::Pe) {
        result.risk =
            unsupportedFile(std::format("Not a PE file: {}.", result.identification.detail));
        result.run.finished = std::chrono::system_clock::now();
        return result;
    }

    notify(progress, AnalysisStage::Parsing);
    {
        // The whole file is needed by the parser; the buffer is released as soon as it is done.
        // Its size is bounded by limits.maxFileBytes, enforced at intake.
        std::vector<std::byte> data(static_cast<std::size_t>(reader.size()));
        if (Status status = reader.readExact(0, data); !status) {
            return std::move(status).error();
        }
        Result<PeImage> image = parser_->parse(data, limits, token);
        if (!image) {
            if (endsAnalysis(image.error()) ||
                image.error().code == ErrorCode::ResourceLimitExceeded) {
                return std::move(image).error();
            }
            result.risk = unsupportedFile(std::format(
                "The PE structures could not be parsed: {}.", image.error().describe()));
            result.run.finished = std::chrono::system_clock::now();
            return result;
        }
        result.pe = std::move(image).value();
    }
    const PeImage& pe = *result.pe;

    notify(progress, AnalysisStage::Sections);
    result.sections = analyzeSections(pe);

    notify(progress, AnalysisStage::Strings);
    if (Result<StringExtraction> strings = extractStrings(reader, limits, token); strings) {
        result.indicators = classifyStrings(strings.value());
        result.strings = std::move(strings).value();
    } else if (endsAnalysis(strings.error())) {
        return std::move(strings).error();
    } else {
        result.warnings.push_back("string extraction failed: " + strings.error().describe());
    }

    notify(progress, AnalysisStage::Entropy);
    if (Result<EntropyReport> entropy =
            analyzeEntropy(reader, result.sections, pe.overlay, limits, token);
        entropy) {
        result.entropy = std::move(entropy).value();
    } else if (endsAnalysis(entropy.error())) {
        return std::move(entropy).error();
    } else {
        result.warnings.push_back("entropy analysis failed: " + entropy.error().describe());
    }

    if (!enrichments_.empty()) {
        notify(progress, AnalysisStage::Enrichment);
        const EnrichmentInput input{path, result.sha256, pe, reader};
        for (const std::shared_ptr<const IEnrichment>& enrichment : enrichments_) {
            if (Status status = checkCancelled(token); !status) {
                return std::move(status).error();
            }
            result.enrichments.push_back(runEnrichment(*enrichment, input, token));
        }
    }

    notify(progress, AnalysisStage::Rules);
    const RuleContext context{
        .image = pe,
        .sections = result.sections,
        .entropy = result.entropy ? &*result.entropy : nullptr,
        .strings = result.strings ? &*result.strings : nullptr,
        .indicators = result.strings ? &result.indicators : nullptr,
    };
    Result<RuleEvaluation> evaluation = rules_.evaluate(context, token);
    if (!evaluation) {
        return std::move(evaluation).error();
    }
    result.findings = std::move(evaluation.value().findings);
    result.skippedRules = std::move(evaluation.value().skipped);
    result.failedRules = std::move(evaluation.value().failed);
    for (const EnrichmentResult& enrichment : result.enrichments) {
        result.findings.insert(result.findings.end(), enrichment.findings.begin(),
                               enrichment.findings.end());
    }

    notify(progress, AnalysisStage::Scoring);
    std::vector<std::string> gaps = coverageGaps(result);
    gaps.insert(gaps.end(), result.warnings.begin(), result.warnings.end());
    result.risk = assessRisk(result.findings, std::move(gaps), options_.scoring);
    result.run.finished = std::chrono::system_clock::now();
    return result;
}

} // namespace sectoryn
