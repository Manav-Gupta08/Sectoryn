#include "detectors/ApiCatalogue.hpp"
#include "detectors/DefaultRules.hpp"
#include "engine/AnalysisEngine.hpp"
#include "parsers/LiefPeParser.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"
#include "utilities/Sha256.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

using namespace std::string_literals;
using test::bytesOf;
using test::PeBuilder;

std::vector<std::string> ruleIds(const AnalysisResult& result) {
    std::vector<std::string> ids;
    for (const Finding& finding : result.findings) {
        ids.push_back(finding.ruleId);
    }
    return ids;
}

bool hasFinding(const AnalysisResult& result, std::string_view id) {
    return std::ranges::any_of(result.findings,
                               [id](const Finding& finding) { return finding.ruleId == id; });
}

std::vector<std::byte> randomBytes(std::size_t count) {
    std::mt19937 generator(7);
    std::uniform_int_distribution<int> byte(0, 255);
    std::vector<std::byte> data(count);
    std::ranges::generate(data, [&] { return static_cast<std::byte>(byte(generator)); });
    return data;
}

std::vector<std::byte> minimalPe() {
    return PeBuilder().addSection(".text", PeBuilder::kCode, bytesOf("x")).build();
}

class EngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        Result<AnalysisEngine> engine = AnalysisEngine::createDefault();
        ASSERT_TRUE(engine.hasValue()) << engine.error().describe();
        engine_.emplace(std::move(engine).value());
    }

    std::filesystem::path write(const std::string& name, const std::vector<std::byte>& data) {
        return dir_.write(name, data);
    }

    Result<AnalysisResult> analyze(const std::vector<std::byte>& data) {
        return engine_->analyze(write("sample.exe", data));
    }

    test::TempDir dir_;
    std::optional<AnalysisEngine> engine_;
};

TEST_F(EngineTest, AnalyzesOrdinaryExecutable) {
    const std::vector<std::byte> file =
        PeBuilder()
            .addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x200, '\x90')))
            .addSection(".rdata", PeBuilder::kReadOnly, bytesOf("Hello from a test program"))
            .addImport("KERNEL32.dll", {"ExitProcess"})
            .build();
    const Result<AnalysisResult> result = analyze(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const AnalysisResult& analysis = result.value();

    const Result<Sha256::Digest> expected = Sha256::hash(file);
    ASSERT_TRUE(expected.hasValue());
    EXPECT_EQ(analysis.sha256, Sha256::toHex(expected.value()));
    EXPECT_EQ(analysis.file.sizeBytes, file.size());
    EXPECT_EQ(analysis.identification.kind, FileKind::Pe);
    ASSERT_TRUE(analysis.pe.has_value());
    EXPECT_EQ(analysis.pe->sections.size(), 3U);
    EXPECT_EQ(analysis.sections.sections.size(), 3U);
    ASSERT_TRUE(analysis.strings.has_value());
    ASSERT_TRUE(analysis.entropy.has_value());
    EXPECT_EQ(analysis.entropy->sections.size(), 3U);

    EXPECT_TRUE(analysis.findings.empty()) << ::testing::PrintToString(ruleIds(analysis));
    EXPECT_TRUE(analysis.risk.coverageGaps.empty())
        << ::testing::PrintToString(analysis.risk.coverageGaps);
    EXPECT_EQ(analysis.risk.outcome, TriageOutcome::NoSignificantIndicators);
    EXPECT_EQ(analysis.engine.parserName, "LIEF");
    EXPECT_FALSE(analysis.engine.version.empty());
    EXPECT_LE(analysis.run.started, analysis.run.finished);
}

TEST_F(EngineTest, ReportsInjectionCapability) {
    const std::vector<std::byte> file =
        PeBuilder(PeFormat::Pe32Plus)
            .addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x200, '\xC3')))
            .addImport("KERNEL32.dll", {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory",
                                        "CreateRemoteThread"})
            .build();
    const Result<AnalysisResult> result = analyze(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    EXPECT_TRUE(hasFinding(result.value(), "api.process_injection"));
    EXPECT_EQ(result.value().risk.outcome, TriageOutcome::SuspiciousIndicators);
}

TEST_F(EngineTest, CombinesPackingIndicators) {
    const std::vector<std::byte> file =
        PeBuilder()
            .addSection("UPX0", 0xE0000080, {}, 0x4000)
            .addSection("UPX1", 0xE0000040, randomBytes(0x2000))
            .entryPoint(0x5000)
            .build();
    const Result<AnalysisResult> result = analyze(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const AnalysisResult& analysis = result.value();

    for (const std::string_view id :
         {"section.writable_executable", "section.packer_name", "entropy.packed_code"}) {
        EXPECT_TRUE(hasFinding(analysis, id)) << id;
    }
    // All three describe packing, so only one of them adds to the score.
    const auto counted = std::ranges::count_if(
        analysis.risk.contributions, [&](const ScoreContribution& contribution) {
            return contribution.counted &&
                   analysis.findings[contribution.findingIndex].correlationGroup == "packing";
        });
    EXPECT_EQ(counted, 1);
}

TEST_F(EngineTest, FindsStringIndicators) {
    const std::vector<std::byte> file =
        PeBuilder()
            .addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x200, '\x90')))
            .addSection(".data", PeBuilder::kReadWrite,
                        bytesOf("powershell -EncodedCommand ZQBjAGgAbwA=\0"
                                "http://update.example.net/payload.bin\0"s))
            .build();
    const Result<AnalysisResult> result = analyze(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    EXPECT_TRUE(hasFinding(result.value(), "strings.powershell"));
    EXPECT_TRUE(hasFinding(result.value(), "strings.network"));
}

TEST_F(EngineTest, NonPeFileIsUnsupported) {
    const Result<AnalysisResult> result = analyze(bytesOf("#!/bin/sh\necho hello\n"));
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    EXPECT_EQ(result.value().risk.outcome, TriageOutcome::UnsupportedOrInvalid);
    EXPECT_FALSE(result.value().pe.has_value());
    EXPECT_EQ(result.value().sha256.size(), 64U);
    EXPECT_TRUE(result.value().findings.empty());
}

TEST_F(EngineTest, TruncatedPeIsInvalid) {
    std::vector<std::byte> file =
        PeBuilder().addSection(".text", PeBuilder::kCode, bytesOf("x")).build();
    file.resize(PeBuilder::kOptionalHeaderOffset + 40);
    const Result<AnalysisResult> result = analyze(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    EXPECT_EQ(result.value().risk.outcome, TriageOutcome::UnsupportedOrInvalid);
    EXPECT_NE(result.value().risk.explanation.find("optional header"), std::string::npos);
}

TEST_F(EngineTest, IntakeErrorsAreReturned) {
    const Result<AnalysisResult> missing = engine_->analyze(dir_.path() / "missing.exe");
    ASSERT_FALSE(missing.hasValue());
    EXPECT_EQ(missing.error().code, ErrorCode::InvalidInput);

    EngineOptions options;
    options.limits.maxFileBytes = 16;
    Result<AnalysisEngine> small = AnalysisEngine::createDefault(options);
    ASSERT_TRUE(small.hasValue());
    const Result<AnalysisResult> tooLarge =
        small.value().analyze(write("big.exe", std::vector<std::byte>(64)));
    ASSERT_FALSE(tooLarge.hasValue());
    EXPECT_EQ(tooLarge.error().code, ErrorCode::ResourceLimitExceeded);
}

TEST_F(EngineTest, HonorsCancellation) {
    const auto path = write("sample.exe", minimalPe());
    CancellationSource source;
    source.request_stop();
    const Result<AnalysisResult> result = engine_->analyze(path, source.get_token());
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::Cancelled);
}

TEST_F(EngineTest, ReportsProgressInOrder) {
    const auto path = write("sample.exe", minimalPe());
    std::vector<AnalysisStage> stages;
    const Result<AnalysisResult> result =
        engine_->analyze(path, {}, [&stages](AnalysisStage stage) { stages.push_back(stage); });
    ASSERT_TRUE(result.hasValue());
    ASSERT_FALSE(stages.empty());
    EXPECT_EQ(stages.front(), AnalysisStage::Opening);
    EXPECT_EQ(stages.back(), AnalysisStage::Scoring);
    EXPECT_TRUE(std::ranges::is_sorted(stages));
}

TEST(EngineOptions, InvalidOptionsAreRejected) {
    EngineOptions options;
    options.scoring.highPriorityThreshold = 10;
    EXPECT_FALSE(AnalysisEngine::createDefault(options).hasValue());

    options = {};
    options.limits.readChunkBytes = 1;
    EXPECT_FALSE(AnalysisEngine::createDefault(options).hasValue());
}

class FixedEnrichment final : public IEnrichment {
public:
    explicit FixedEnrichment(bool fail)
        : fail_(fail) {}

    [[nodiscard]] std::string_view id() const noexcept override { return "fixed"; }
    [[nodiscard]] std::string_view displayName() const noexcept override { return "Fixed"; }

    [[nodiscard]] EnrichmentResult run(const EnrichmentInput& input,
                                       const CancellationToken&) const override {
        if (fail_) {
            throw std::runtime_error("service down");
        }
        EnrichmentResult result;
        result.id = "fixed";
        result.displayName = "Fixed";
        result.status = FieldStatus::present();
        result.properties.push_back({"sha256", input.sha256});
        result.findings.push_back({.ruleId = "fixed.match",
                                   .title = "Fixed match",
                                   .severity = Severity::High,
                                   .confidence = Confidence::High});
        return result;
    }

private:
    bool fail_;
};

TEST(EngineEnrichment, ResultsAndFailuresAreRecorded) {
    const test::TempDir dir;
    const auto path =
        dir.write("a.exe", PeBuilder().addSection(".text", PeBuilder::kCode, bytesOf("x")).build());

    Result<ApiCatalogue> catalogue = ApiCatalogue::builtIn();
    ASSERT_TRUE(catalogue.hasValue());
    Result<RuleRegistry> rules = createDefaultRules(std::move(catalogue).value());
    ASSERT_TRUE(rules.hasValue());
    Result<AnalysisEngine> engine = AnalysisEngine::create(
        {}, std::make_unique<LiefPeParser>(), std::move(rules).value(),
        {std::make_shared<FixedEnrichment>(false), std::make_shared<FixedEnrichment>(true)});
    ASSERT_TRUE(engine.hasValue()) << engine.error().describe();

    const Result<AnalysisResult> result = engine.value().analyze(path);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const AnalysisResult& analysis = result.value();

    ASSERT_EQ(analysis.enrichments.size(), 2U);
    EXPECT_EQ(analysis.enrichments[0].properties[0].value, analysis.sha256);
    EXPECT_EQ(analysis.enrichments[1].status.state, FieldState::ParserError);
    EXPECT_TRUE(hasFinding(analysis, "fixed.match"));
    EXPECT_FALSE(analysis.risk.coverageGaps.empty());
}

TEST(EngineEnrichment, NullEnrichmentIsRejected) {
    EXPECT_FALSE(AnalysisEngine::create({}, std::make_unique<LiefPeParser>(), RuleRegistry{},
                                        {nullptr})
                     .hasValue());
    EXPECT_FALSE(AnalysisEngine::create({}, nullptr, RuleRegistry{}).hasValue());
}

// Real Microsoft-built binaries, where the host has them. Only properties that hold for every
// Windows version are checked; findings vary between builds and are not asserted.
TEST(EngineSystemBinaries, ParsesWindowsBinaries) {
    const std::filesystem::path system32 = "C:/Windows/System32";
    std::vector<std::filesystem::path> files;
    for (const char* name : {"kernel32.dll", "ntdll.dll", "notepad.exe", "user32.dll"}) {
        if (std::filesystem::exists(system32 / name)) {
            files.push_back(system32 / name);
        }
    }
    if (files.empty()) {
        GTEST_SKIP() << "no Windows system binaries on this host";
    }

    Result<AnalysisEngine> engine = AnalysisEngine::createDefault();
    ASSERT_TRUE(engine.hasValue());
    for (const std::filesystem::path& file : files) {
        const Result<AnalysisResult> result = engine.value().analyze(file);
        ASSERT_TRUE(result.hasValue()) << file << ": " << result.error().describe();
        const AnalysisResult& analysis = result.value();
        EXPECT_NE(analysis.risk.outcome, TriageOutcome::UnsupportedOrInvalid) << file;
        ASSERT_TRUE(analysis.pe.has_value()) << file;
        EXPECT_EQ(analysis.pe->sectionTable.state, FieldState::Present) << file;
        EXPECT_FALSE(analysis.pe->sections.empty()) << file;
        // ntdll.dll imports nothing, so "absent" is a valid outcome; a read failure is not.
        const FieldStatus& imports = analysis.pe->imports.status;
        EXPECT_TRUE(imports.hasData() || imports.state == FieldState::Absent)
            << file << ": " << imports.detail;
        EXPECT_TRUE(analysis.failedRules.empty()) << file;
        EXPECT_TRUE(analysis.warnings.empty()) << file;
    }
}

} // namespace
} // namespace sectoryn
