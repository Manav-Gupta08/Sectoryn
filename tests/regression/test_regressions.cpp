#include "engine/AnalysisEngine.hpp"
#include "parsers/PeConstants.hpp"
#include "reports/HtmlReport.hpp"
#include "reports/JsonReport.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"

#include <nlohmann/json.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

// End-to-end cases for hostile inputs: every file goes through the full engine and both report
// writers. Each test pins down behavior that once went wrong or is easy to break.
namespace sectoryn {
namespace {

using namespace std::string_literals;
using test::bytesOf;
using test::PeBuilder;
using test::writeLe16;
using test::writeLe32;

constexpr std::size_t kNumberOfSectionsField = PeBuilder::kCoffHeaderOffset + 2;

class Regression : public ::testing::Test {
protected:
    void SetUp() override {
        Result<AnalysisEngine> engine = AnalysisEngine::createDefault();
        ASSERT_TRUE(engine.hasValue()) << engine.error().describe();
        engine_.emplace(std::move(engine).value());
    }

    Result<AnalysisResult> analyze(const std::vector<std::byte>& file,
                                   std::string_view name = "sample.exe") {
        return engine_->analyze(dir_.write(name, file));
    }

    // Analyzes the file and checks that both reports render and the JSON one parses.
    AnalysisResult analyzeAndReport(const std::vector<std::byte>& file) {
        Result<AnalysisResult> result = analyze(file);
        EXPECT_TRUE(result.hasValue()) << result.error().describe();
        if (!result) {
            return {};
        }
        ReportOptions options;
        options.includeStrings = true;
        EXPECT_TRUE(nlohmann::json::accept(renderJsonReport(result.value(), options)));
        EXPECT_FALSE(renderHtmlReport(result.value(), options).empty());
        return std::move(result).value();
    }

    test::TempDir dir_;
    std::optional<AnalysisEngine> engine_;
};

PeBuilder sampleBuilder() {
    PeBuilder builder;
    builder.addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x200, '\x90')))
        .addSection(".data", PeBuilder::kReadWrite, bytesOf("data"))
        .addImport("KERNEL32.dll", {"ExitProcess"});
    return builder;
}

std::uint32_t readLe32(const std::vector<std::byte>& data, std::size_t offset) {
    std::uint32_t value = 0;
    for (std::size_t i = 4; i > 0; --i) {
        value = (value << 8U) | std::to_integer<std::uint32_t>(data[offset + i - 1]);
    }
    return value;
}

bool hasIssue(const AnalysisResult& result, std::string_view code) {
    return result.pe && std::ranges::any_of(result.pe->issues, [code](const StructuralIssue& i) {
               return i.code == code;
           });
}

TEST_F(Regression, EmptyFileIsRejectedWithAReason) {
    const Result<AnalysisResult> result = analyze({});
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidInput);
}

TEST_F(Regression, SectionRangeNearFourGigabytesDoesNotWrap) {
    const PeBuilder builder = sampleBuilder();
    std::vector<std::byte> file = builder.build();
    const std::size_t header = builder.sectionHeaderOffset(0);
    writeLe32(file, header + 16, 0x1000);     // SizeOfRawData
    writeLe32(file, header + 20, 0xFFFFF800); // PointerToRawData
    const AnalysisResult result = analyzeAndReport(file);
    ASSERT_TRUE(result.pe.has_value());
    EXPECT_TRUE(std::ranges::any_of(result.findings, [](const Finding& f) {
        return f.ruleId == "section.data_outside_file";
    }));
}

TEST_F(Regression, CertificateTableNearFourGigabytesDoesNotWrap) {
    const PeBuilder builder = sampleBuilder();
    std::vector<std::byte> file = builder.build();
    const std::size_t entry = builder.dataDirectoryOffset(pe::kCertificateDirectory);
    writeLe32(file, entry, 0xFFFFFFF8);
    writeLe32(file, entry + 4, 0x10);
    const AnalysisResult result = analyzeAndReport(file);
    ASSERT_TRUE(result.pe.has_value());
    EXPECT_EQ(result.pe->certificate.status.state, FieldState::Invalid);
    EXPECT_TRUE(hasIssue(result, "header.certificate_table"));
    EXPECT_FALSE(std::ranges::any_of(result.findings, [](const Finding& f) {
        return f.ruleId == "signature.data_after_certificate";
    }));
}

TEST_F(Regression, MaximumSectionCountIsBounded) {
    std::vector<std::byte> file = sampleBuilder().build();
    writeLe16(file, kNumberOfSectionsField, 0xFFFF);
    const Result<AnalysisResult> result = analyze(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    if (result.value().pe) {
        EXPECT_LE(result.value().pe->sections.size(), AnalysisLimits{}.maxSections);
    } else {
        EXPECT_EQ(result.value().risk.outcome, TriageOutcome::UnsupportedOrInvalid);
    }
}

TEST_F(Regression, OverlappingSectionsShareRawDataSafely) {
    PeBuilder builder;
    for (int i = 0; i < 40; ++i) {
        builder.addSection(".s" + std::to_string(i), PeBuilder::kReadOnly,
                           bytesOf(std::string(0x200, static_cast<char>(i))));
    }
    std::vector<std::byte> file = builder.build();
    const std::size_t first = builder.sectionHeaderOffset(0);
    const std::uint32_t raw = readLe32(file, first + 20);
    for (std::size_t i = 1; i < builder.sectionCount(); ++i) {
        writeLe32(file, builder.sectionHeaderOffset(i) + 20, raw);
    }
    const AnalysisResult result = analyzeAndReport(file);
    ASSERT_TRUE(result.pe.has_value());
    ASSERT_TRUE(result.entropy.has_value());
}

TEST_F(Regression, MarkupInSectionNamesAndStringsIsEscaped) {
    const std::vector<std::byte> file =
        PeBuilder()
            .addSection("<script>", PeBuilder::kCode, bytesOf(std::string(0x40, '\xC3')))
            .addSection(".data", PeBuilder::kReadOnly,
                        bytesOf("<img src=x onerror=alert(1)>\0javascript:alert(1)\0"s))
            .build();
    const Result<AnalysisResult> result = analyze(file);
    ASSERT_TRUE(result.hasValue());
    ReportOptions options;
    options.includeStrings = true;
    const std::string html = renderHtmlReport(result.value(), options);
    EXPECT_EQ(html.find("<script>"), std::string::npos);
    EXPECT_EQ(html.find("<img src=x"), std::string::npos);
    EXPECT_NE(html.find("&lt;script&gt;"), std::string::npos);
}

TEST_F(Regression, ControlCharactersKeepJsonValid) {
    const std::vector<std::byte> file =
        PeBuilder()
            .addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x40, '\xC3')))
            .exports("odd\x01\x7F\"name\\.dll", {"Fn\x1B[31m", "\xFF\xFE"})
            .build();
    static_cast<void>(analyzeAndReport(file));
}

TEST_F(Regression, ImportNamesWithoutTerminatorAtEndOfFile) {
    std::vector<std::byte> file = sampleBuilder().build();
    // Cut the file inside the import directory data that follows the sections.
    file.resize(file.size() - 0x20);
    const Result<AnalysisResult> result = analyze(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
}

TEST_F(Regression, SameFileGivesTheSameReportWithoutRunTimes) {
    const std::filesystem::path path = dir_.write("same.exe", sampleBuilder().build());
    const Result<AnalysisResult> first = engine_->analyze(path);
    const Result<AnalysisResult> second = engine_->analyze(path);
    ASSERT_TRUE(first.hasValue());
    ASSERT_TRUE(second.hasValue());
    ReportOptions options;
    options.includeRunTimes = false;
    EXPECT_EQ(renderJsonReport(first.value(), options), renderJsonReport(second.value(), options));
}

} // namespace
} // namespace sectoryn
