#include "engine/AnalysisEngine.hpp"
#include "reports/HtmlReport.hpp"
#include "reports/JsonReport.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {
namespace {

using test::bytesOf;
using test::PeBuilder;

const std::string kHostileName = "<img src=x onerror=alert(1)>.exe";
const std::string kHostileTitle = "<script>alert('t')</script>";
const std::string kHostileString = "</style><script>alert(1)</script>";

std::string lowercase(std::string text) {
    std::ranges::transform(text, text.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::size_t occurrences(std::string_view text, std::string_view needle) {
    std::size_t count = 0;
    for (auto at = text.find(needle); at != std::string_view::npos;
         at = text.find(needle, at + needle.size())) {
        ++count;
    }
    return count;
}

// Every piece of text a file controls carries markup, so any escaping gap shows up as a tag.
AnalysisResult hostileResult() {
    AnalysisResult result;
    result.file.path = std::filesystem::path("samples") / kHostileName;
    result.file.sizeBytes = 4096;
    result.sha256 = std::string(64, 'a');
    result.identification = {FileKind::Pe, "PE signature at 0x80", 0x80};

    PeImage pe;
    pe.fileSize = 4096;
    pe.sectionTable = FieldStatus::present();
    Section section;
    section.name = kHostileString;
    pe.sections.push_back(section);
    pe.imports.status = FieldStatus::present();
    pe.imports.modules.push_back({"<b>evil.dll</b>", false, {{"\"onload=\"x", std::nullopt, 0}}});
    pe.exports.status = FieldStatus::present();
    pe.exports.dllName = "<iframe src=//example.invalid>";
    pe.exports.functions.push_back({"Run", 1, 0x1000, std::string("<x>.y")});
    pe.issues.push_back({"header.<code>", "<marquee>issue</marquee>"});
    result.pe = std::move(pe);
    result.sections.sections.resize(1);

    Finding finding;
    finding.ruleId = "test.hostile";
    finding.title = kHostileTitle;
    finding.description = "line one\nline two";
    finding.severity = Severity::High;
    finding.confidence = Confidence::Medium;
    finding.evidence.push_back({"</td></tr></table><iframe>", 0x40, "section <0>"});
    finding.attack.push_back({"T1055", "<i>Process Injection</i>"});
    result.findings.push_back(finding);

    StringExtraction strings;
    strings.strings.push_back({0x200, StringEncoding::Ascii, kHostileString, false});
    strings.strings.push_back({0x300, StringEncoding::Ascii, "bad\xFF\xFE" "bytes", false});
    result.strings = std::move(strings);
    result.indicators.push_back(
        {IndicatorKind::Url, "http://example.invalid/\"><script>", 0, 0x200});

    EnrichmentResult enrichment;
    enrichment.id = "test";
    enrichment.displayName = "<h1>Check</h1>";
    enrichment.status = FieldStatus::present();
    enrichment.properties.emplace_back("Signer", "<svg onload=alert(1)>");
    result.enrichments.push_back(std::move(enrichment));

    result.warnings.emplace_back("<marquee>warning</marquee>");
    result.skippedRules.push_back({"rule.<x>", "<blink>"});
    result.risk.outcome = TriageOutcome::SuspiciousIndicators;
    result.risk.score = 30.0;
    result.risk.explanation = "<script>explanation</script>";
    result.risk.contributions.push_back({0, "test.hostile", 22.5, true, {}});

    result.engine = {"0.1.0", "LIEF", "0.17.6"};
    const auto start = std::chrono::sys_days{std::chrono::year{2026} / 10 / 27};
    result.run = {start, start + std::chrono::milliseconds(1234)};
    return result;
}

ReportOptions withStrings() {
    ReportOptions options;
    options.includeStrings = true;
    return options;
}

TEST(HtmlReport, EscapesEverythingTakenFromTheFile) {
    const std::string html = lowercase(renderHtmlReport(hostileResult(), withStrings()));

    for (const std::string_view tag :
         {"<script", "<iframe", "<img", "<svg onload", "<marquee", "<blink", "<b>", "<i>", "<x>",
          "<h1>check", "<code>\""}) {
        EXPECT_EQ(html.find(tag), std::string::npos) << tag;
    }
    EXPECT_EQ(occurrences(html, "</style>"), 1U);
    EXPECT_NE(html.find("&lt;script&gt;alert(&#39;t&#39;)&lt;/script&gt;"), std::string::npos);
    EXPECT_NE(html.find("&lt;img src=x onerror=alert(1)&gt;.exe"), std::string::npos);
    EXPECT_NE(html.find("&quot;onload=&quot;x"), std::string::npos);
}

TEST(HtmlReport, HasNoScriptsOrExternalReferences) {
    const std::string html = lowercase(renderHtmlReport(hostileResult(), withStrings()));

    EXPECT_NE(html.find("content-security-policy"), std::string::npos);
    EXPECT_NE(html.find("default-src 'none'"), std::string::npos);
    EXPECT_EQ(html.find("src=\""), std::string::npos);
    EXPECT_EQ(html.find("<link"), std::string::npos);
    EXPECT_EQ(html.find("url("), std::string::npos);
    constexpr std::string_view kHref = "href=\"";
    for (auto at = html.find(kHref); at != std::string::npos; at = html.find(kHref, at + 1)) {
        EXPECT_EQ(html.at(at + kHref.size()), '#') << "only in-page links are allowed";
    }
}

TEST(HtmlReport, ReplacesInvalidUtf8) {
    const std::string html = renderHtmlReport(hostileResult(), withStrings());
    EXPECT_NE(html.find("bad\xEF\xBF\xBD\xEF\xBF\xBD" "bytes"), std::string::npos);
}

TEST(HtmlReport, LeavesOutStringsAndRunTimesWhenAsked) {
    ReportOptions options;
    options.includeRunTimes = false;
    const std::string html = renderHtmlReport(hostileResult(), options);
    EXPECT_EQ(html.find("Extracted strings"), std::string::npos);
    EXPECT_EQ(html.find("Analysis started"), std::string::npos);
    // Indicators are part of the report regardless.
    EXPECT_NE(html.find("http://example.invalid/&quot;&gt;&lt;script&gt;"), std::string::npos);
}

TEST(HtmlReport, ShowsOnlyTheFileNameByDefault) {
    const AnalysisResult result = hostileResult();
    EXPECT_EQ(renderHtmlReport(result).find("samples"), std::string::npos);

    ReportOptions options;
    options.includeFilePath = true;
    EXPECT_NE(renderHtmlReport(result, options).find("samples"), std::string::npos);
}

TEST(JsonReport, KeepsTextExactAndStaysValid) {
    const std::string text = renderJsonReport(hostileResult(), withStrings());
    ASSERT_FALSE(text.empty());
    EXPECT_EQ(text.back(), '\n');

    const nlohmann::json json = nlohmann::json::parse(text);
    EXPECT_EQ(json["schema"], "sectoryn-report");
    EXPECT_EQ(json["schema_version"], kJsonReportSchemaVersion);
    EXPECT_EQ(json["file"]["name"], kHostileName);
    EXPECT_EQ(json["findings"][0]["title"], kHostileTitle);
    EXPECT_EQ(json["findings"][0]["severity"], "high");
    EXPECT_EQ(json["findings"][0]["evidence"][0]["file_offset"], 0x40);
    EXPECT_EQ(json["assessment"]["outcome"], "suspicious_indicators");
    EXPECT_EQ(json["pe"]["sections"][0]["name"], kHostileString);
    EXPECT_TRUE(json["pe"]["sections"][0]["entropy"].is_null());
    EXPECT_EQ(json["strings"]["items"][0]["text"], kHostileString);
    EXPECT_EQ(json["strings"]["items"][1]["text"], "bad\xEF\xBF\xBD\xEF\xBF\xBD" "bytes");
    EXPECT_EQ(json["run"]["duration_ms"], 1234);
    EXPECT_EQ(json["run"]["started"], "2026-10-27T00:00:00.000Z");
}

TEST(JsonReport, KeepsKeysInDocumentedOrder) {
    const nlohmann::ordered_json json = buildJsonReport(hostileResult());
    std::vector<std::string> keys;
    for (const auto& item : json.items()) {
        keys.push_back(item.key());
    }
    const std::vector<std::string> expected = {
        "schema", "schema_version", "generator", "run", "file", "identification", "assessment",
        "findings", "rules", "warnings", "pe", "entropy", "strings", "indicators", "enrichments"};
    EXPECT_EQ(keys, expected);
}

TEST(JsonReport, HonorsOptions) {
    ReportOptions options;
    options.includeRunTimes = false;
    const nlohmann::ordered_json json = buildJsonReport(hostileResult(), options);
    EXPECT_FALSE(json.contains("run"));
    EXPECT_EQ(json["strings"]["count"], 2);
    EXPECT_FALSE(json["strings"].contains("items"));

    options.includeFilePath = true;
    const auto name = buildJsonReport(hostileResult(), options)["file"]["name"].get<std::string>();
    EXPECT_NE(name.find("samples"), std::string::npos);
}

TEST(ReportCommon, FormatsTimestamps) {
    EXPECT_EQ(formatCoffTimestamp(0), "0 (not set)");
    EXPECT_EQ(formatCoffTimestamp(1600000000), "2020-09-13 12:26:40 UTC (0x5F5E1000)");
    EXPECT_NE(formatCoffTimestamp(0xFFFFFFFF).find("not a plausible date"), std::string::npos);

    const auto time = std::chrono::sys_days{std::chrono::year{2026} / 10 / 27} +
                      std::chrono::hours(14) + std::chrono::minutes(3) +
                      std::chrono::milliseconds(12415);
    EXPECT_EQ(formatUtc(time), "2026-10-27T14:03:12.415Z");
}

class ReportEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        Result<AnalysisEngine> engine = AnalysisEngine::createDefault();
        ASSERT_TRUE(engine.hasValue()) << engine.error().describe();
        engine_.emplace(std::move(engine).value());
    }

    AnalysisResult analyze(const std::vector<std::byte>& data) {
        return analyzePath(dir_.write("sample.dll", data));
    }

    AnalysisResult analyzePath(const std::filesystem::path& path) {
        const Result<AnalysisResult> result = engine_->analyze(path);
        EXPECT_TRUE(result.hasValue()) << result.error().describe();
        return result.hasValue() ? result.value() : AnalysisResult{};
    }

    test::TempDir dir_;
    std::optional<AnalysisEngine> engine_;
};

std::vector<std::byte> samplePe() {
    return PeBuilder()
        .characteristics(0x2102)
        .addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x400, '\x90')))
        .addSection(".rdata", PeBuilder::kReadOnly, bytesOf("https://example.invalid/update"))
        .addImport("KERNEL32.dll", {"GetProcAddress", "LoadLibraryA"})
        .exports("sample.dll", {"Alpha", "Beta"})
        .overlay(bytesOf("trailing data"))
        .build();
}

TEST_F(ReportEngineTest, DescribesAnalyzedPe) {
    const AnalysisResult result = analyze(samplePe());
    const nlohmann::ordered_json json = buildJsonReport(result);

    EXPECT_EQ(json["identification"]["kind"], "pe");
    EXPECT_EQ(json["pe"]["format"], "pe32");
    ASSERT_GE(json["pe"]["sections"].size(), 2U);
    EXPECT_EQ(json["pe"]["sections"][0]["name"], ".text");
    EXPECT_EQ(json["pe"]["sections"][0]["permissions"], "R-X");
    EXPECT_TRUE(json["pe"]["sections"][0]["entropy"]["entropy"].is_number());
    EXPECT_EQ(json["pe"]["imports"]["modules"][0]["name"], "KERNEL32.dll");
    EXPECT_EQ(json["pe"]["exports"]["functions"].size(), 2U);
    EXPECT_EQ(json["pe"]["overlay"]["status"]["state"], "present");
    EXPECT_EQ(json["file"]["sha256"], result.sha256);

    const std::string html = renderHtmlReport(result);
    EXPECT_NE(html.find("KERNEL32.dll"), std::string::npos);
    EXPECT_NE(html.find("<svg class=\"profile\""), std::string::npos);
    EXPECT_NE(html.find("href=\"#headers\""), std::string::npos);
}

TEST_F(ReportEngineTest, IsReproducibleWithoutRunTimes) {
    const std::filesystem::path file = dir_.write("sample.dll", samplePe());
    const AnalysisResult first = analyzePath(file);
    const AnalysisResult second = analyzePath(file);

    ReportOptions options = withStrings();
    options.includeRunTimes = false;
    EXPECT_EQ(renderJsonReport(first, options), renderJsonReport(second, options));
    EXPECT_EQ(renderHtmlReport(first, options), renderHtmlReport(second, options));
}

TEST_F(ReportEngineTest, DescribesFilesThatAreNotPe) {
    const AnalysisResult result = analyze(bytesOf("just some text, not an executable"));
    const nlohmann::ordered_json json = buildJsonReport(result);
    EXPECT_TRUE(json["pe"].is_null());
    EXPECT_EQ(json["assessment"]["outcome"], "unsupported_or_invalid");

    const std::string html = renderHtmlReport(result);
    EXPECT_EQ(html.find("href=\"#headers\""), std::string::npos);
    EXPECT_NE(html.find("Unsupported or invalid file"), std::string::npos);
}

} // namespace
} // namespace sectoryn
