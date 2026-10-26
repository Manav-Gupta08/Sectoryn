#include "support/TempDir.hpp"

#include <gtest/gtest.h>

#ifdef SECTORYN_HAVE_YARA

#include "detectors/yara/YaraCompiler.hpp"
#include "detectors/yara/YaraScanner.hpp"
#include "engine/AnalysisEngine.hpp"
#include "engine/yara/YaraEnrichment.hpp"
#include "support/PeBuilder.hpp"

#include <array>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace sectoryn {
namespace {

constexpr const char* kRules = R"(
rule EmbeddedMarker : test marker
{
    meta:
        description = "Contains the Sectoryn test marker"
        severity = "low"
        version = 3
        reviewed = true
    strings:
        $marker = "SECTORYN-TEST-MARKER"
        $wide = "wide-marker" wide
    condition:
        any of them
}

rule NeverMatches
{
    condition:
        filesize == 0
}
)";

YaraCompilation compile(std::vector<YaraSource> sources) {
    Result<YaraCompilation> compiled = compileYaraRules(sources);
    EXPECT_TRUE(compiled.hasValue()) << compiled.error().describe();
    return compiled.hasValue() ? std::move(compiled).value() : YaraCompilation{};
}

std::shared_ptr<const YaraRuleSet> testRules() {
    YaraCompilation compilation = compile({{.name = "test.yar", .text = kRules}});
    EXPECT_NE(compilation.rules, nullptr);
    return compilation.rules;
}

TEST(YaraCompiler, CompilesValidRules) {
    const auto rules = testRules();
    ASSERT_NE(rules, nullptr);
    EXPECT_EQ(rules->ruleCount(), 2U);
}

TEST(YaraCompiler, ReportsErrorsWithLineNumbers) {
    const YaraCompilation compilation =
        compile({{.name = "good.yar", .text = "rule A { condition: true }"},
                 {.name = "broken.yar", .text = "rule B {\n  condition:\n    undefined_thing\n}"}});
    EXPECT_EQ(compilation.rules, nullptr);
    ASSERT_FALSE(compilation.diagnostics.empty());
    const YaraDiagnostic& error = compilation.diagnostics.front();
    EXPECT_FALSE(error.warning);
    EXPECT_EQ(error.source, "broken.yar");
    EXPECT_EQ(error.line, 3);
    EXPECT_NE(error.message.find("undefined_thing"), std::string::npos);
}

TEST(YaraCompiler, RefusesIncludes) {
    const test::TempDir dir;
    const auto other = dir.write("other.yar", "rule Other { condition: true }");
    const std::string text = "include \"" + other.generic_string() + "\"\n";
    const YaraCompilation compilation = compile({{.name = "main.yar", .text = text}});
    EXPECT_EQ(compilation.rules, nullptr);
    ASSERT_FALSE(compilation.diagnostics.empty());
    EXPECT_NE(compilation.diagnostics.front().message.find("includes are disabled"),
              std::string::npos);
}

TEST(YaraCompiler, KeepsEqualRuleNamesInSeparateNamespaces) {
    const YaraCompilation compilation =
        compile({{.name = "a.yar", .text = "rule Same { condition: true }"},
                 {.name = "b.yar", .text = "rule Same { condition: true }"}});
    ASSERT_NE(compilation.rules, nullptr);
    EXPECT_EQ(compilation.rules->ruleCount(), 2U);
}

TEST(YaraCompiler, CompilesRuleFiles) {
    const test::TempDir dir;
    const std::array files = {dir.write("one.yar", "rule One { condition: true }"),
                              dir.write("two.yar", "rule Two { condition: false }")};
    const Result<YaraCompilation> compiled = compileYaraRuleFiles(files);
    ASSERT_TRUE(compiled.hasValue()) << compiled.error().describe();
    ASSERT_NE(compiled.value().rules, nullptr);
    EXPECT_EQ(compiled.value().rules->ruleCount(), 2U);

    const std::array missing = {dir.path() / "missing.yar"};
    EXPECT_FALSE(compileYaraRuleFiles(missing).hasValue());
}

TEST(YaraCompiler, EnforcesSizeLimits) {
    const std::vector<YaraSource> tooLarge = {
        {.name = "big.yar", .text = std::string(YaraLimits::kMaxSourceBytes + 1, ' ')}};
    const Result<YaraCompilation> compiled = compileYaraRules(tooLarge);
    ASSERT_FALSE(compiled.hasValue());
    EXPECT_EQ(compiled.error().code, ErrorCode::ResourceLimitExceeded);
}

TEST(YaraScanner, ReportsMatchesWithMetadataAndOffsets) {
    const auto rules = testRules();
    ASSERT_NE(rules, nullptr);
    const test::TempDir dir;
    const std::string content = std::string(100, 'x') + "SECTORYN-TEST-MARKER" + "tail";
    const auto file = dir.write("sample.bin", content);

    const Result<YaraScanResult> scanned = scanFileWithYara(*rules, file, {});
    ASSERT_TRUE(scanned.hasValue()) << scanned.error().describe();
    ASSERT_EQ(scanned.value().matches.size(), 1U);
    const YaraMatch& match = scanned.value().matches.front();
    EXPECT_EQ(match.rule, "EmbeddedMarker");
    EXPECT_EQ(match.ruleNamespace, "test.yar");
    EXPECT_EQ(match.tags, (std::vector<std::string>{"test", "marker"}));
    ASSERT_EQ(match.metadata.size(), 4U);
    EXPECT_EQ(match.metadata[0].name, "description");
    EXPECT_EQ(match.metadata[2].value, "3");
    EXPECT_EQ(match.metadata[3].value, "true");
    ASSERT_EQ(match.strings.size(), 1U);
    EXPECT_EQ(match.strings[0].identifier, "$marker");
    EXPECT_EQ(match.strings[0].offset, 100U);
    EXPECT_EQ(match.strings[0].length, 20U);
}

TEST(YaraScanner, FindsNothingInUnrelatedFiles) {
    const auto rules = testRules();
    ASSERT_NE(rules, nullptr);
    const test::TempDir dir;
    const Result<YaraScanResult> scanned =
        scanFileWithYara(*rules, dir.write("plain.txt", "nothing to see"), {});
    ASSERT_TRUE(scanned.hasValue()) << scanned.error().describe();
    EXPECT_TRUE(scanned.value().matches.empty());
}

TEST(YaraScanner, HandlesNonAsciiPaths) {
    const auto rules = testRules();
    ASSERT_NE(rules, nullptr);
    const test::TempDir dir;
    const auto file = dir.path() / std::filesystem::path(u8"\u00e9chantillon-\u6837\u672c.bin");
    std::ofstream(file, std::ios::binary) << "SECTORYN-TEST-MARKER";
    const Result<YaraScanResult> scanned = scanFileWithYara(*rules, file, {});
    ASSERT_TRUE(scanned.hasValue()) << scanned.error().describe();
    EXPECT_EQ(scanned.value().matches.size(), 1U);
}

TEST(YaraScanner, FailsCleanlyForMissingFiles) {
    const auto rules = testRules();
    ASSERT_NE(rules, nullptr);
    const test::TempDir dir;
    const Result<YaraScanResult> scanned = scanFileWithYara(*rules, dir.path() / "missing", {});
    ASSERT_FALSE(scanned.hasValue());
    EXPECT_EQ(scanned.error().code, ErrorCode::IoFailure);
}

TEST(YaraScanner, HonorsCancellation) {
    const auto rules = testRules();
    ASSERT_NE(rules, nullptr);
    const test::TempDir dir;
    CancellationSource source;
    source.request_stop();
    const Result<YaraScanResult> scanned =
        scanFileWithYara(*rules, dir.write("f.bin", "SECTORYN-TEST-MARKER"), source.get_token());
    ASSERT_FALSE(scanned.hasValue());
    EXPECT_EQ(scanned.error().code, ErrorCode::Cancelled);
}

TEST(YaraScanner, SharesRulesAcrossThreads) {
    const auto rules = testRules();
    ASSERT_NE(rules, nullptr);
    const test::TempDir dir;
    const auto file = dir.write("shared.bin", "..SECTORYN-TEST-MARKER..");
    std::vector<std::jthread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            for (int round = 0; round < 10; ++round) {
                const Result<YaraScanResult> scanned = scanFileWithYara(*rules, file, {});
                EXPECT_TRUE(scanned.hasValue() && scanned.value().matches.size() == 1);
            }
        });
    }
}

TEST(YaraEnrichment, TurnsMatchesIntoFindings) {
    YaraMatch match;
    match.rule = "Injector";
    match.ruleNamespace = "family.yar";
    match.metadata = {{.name = "Description", .value = "Known injector loader"},
                      {.name = "severity", .value = "HIGH"},
                      {.name = "mitre_attack", .value = "T1055, T1055.012;bogus T99"}};
    match.strings = {{.identifier = "$api", .offset = 0x400, .length = 12}};

    const Finding finding = findingForYaraMatch(match);
    EXPECT_EQ(finding.ruleId, "yara.Injector");
    EXPECT_EQ(finding.description, "Known injector loader");
    EXPECT_EQ(finding.severity, Severity::High);
    EXPECT_EQ(finding.correlationGroup, "yara");
    ASSERT_EQ(finding.attack.size(), 2U);
    EXPECT_EQ(finding.attack[1].id, "T1055.012");
    ASSERT_EQ(finding.evidence.size(), 1U);
    EXPECT_EQ(finding.evidence[0].fileOffset, 0x400U);

    match.metadata.clear();
    EXPECT_EQ(findingForYaraMatch(match).severity, Severity::Medium);
}

TEST(YaraEnrichment, ReportsMatchesThroughTheEngine) {
    const auto rules = testRules();
    ASSERT_NE(rules, nullptr);
    Result<AnalysisEngine> engine = AnalysisEngine::createDefault(
        {}, {std::make_shared<const YaraEnrichment>(rules)});
    ASSERT_TRUE(engine.hasValue()) << engine.error().describe();

    const test::TempDir dir;
    const auto file = dir.write("marked.exe", test::PeBuilder()
                                                   .addSection(".rdata", test::PeBuilder::kReadOnly,
                                                               test::bytesOf("SECTORYN-TEST-MARKER"))
                                                   .build());
    const Result<AnalysisResult> result = engine.value().analyze(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();

    ASSERT_EQ(result.value().enrichments.size(), 1U);
    const EnrichmentResult& yara = result.value().enrichments.front();
    EXPECT_EQ(yara.id, "yara");
    EXPECT_EQ(yara.status.state, FieldState::Present);
    EXPECT_FALSE(yara.usedNetwork);
    ASSERT_EQ(yara.findings.size(), 1U);
    EXPECT_EQ(yara.findings.front().ruleId, "yara.EmbeddedMarker");
    EXPECT_EQ(yara.findings.front().severity, Severity::Low);
}

} // namespace
} // namespace sectoryn

#endif
