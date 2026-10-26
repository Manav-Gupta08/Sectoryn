#include "engine/AnalysisEngine.hpp"
#include "reports/BatchExporter.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <fstream>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

std::vector<BatchEntry> sampleEntries() {
    BatchEntry completed;
    completed.id = 1;
    completed.path = std::filesystem::path("samples") / "=HYPERLINK(\"x\").exe";
    completed.state = JobState::Completed;
    completed.sha256 = std::string(64, 'a');
    completed.outcome = TriageOutcome::SuspiciousIndicators;
    completed.score = 27.5;
    completed.findings = 4;

    BatchEntry duplicate;
    duplicate.id = 2;
    duplicate.path = "copy.exe";
    duplicate.state = JobState::Duplicate;
    duplicate.sha256 = completed.sha256;
    duplicate.duplicateOf = 1;
    duplicate.message = "same content as job 1";

    BatchEntry failed;
    failed.id = 3;
    failed.path = "missing.exe";
    failed.state = JobState::Failed;
    failed.message = "-cannot open, \"quoted\"";
    return {completed, duplicate, failed};
}

TEST(BatchExport, CsvQuotesCellsAndDefusesFormulas) {
    const std::string csv = renderBatchCsv(sampleEntries());
    EXPECT_TRUE(csv.starts_with("\"job\",\"file\",\"state\""));
    EXPECT_NE(csv.find("\"'=HYPERLINK(\"\"x\"\").exe\""), std::string::npos);
    EXPECT_NE(csv.find("\"'-cannot open, \"\"quoted\"\"\""), std::string::npos);
    EXPECT_NE(csv.find("\"suspicious_indicators\",\"27.5\",\"4\""), std::string::npos);
    EXPECT_NE(csv.find("\"duplicate\""), std::string::npos);
    EXPECT_EQ(csv.find("samples"), std::string::npos) << "only names unless paths are allowed";
    EXPECT_EQ(std::ranges::count(csv, '\n'), 4);
}

TEST(BatchExport, JsonListsEveryJob) {
    const nlohmann::json json = nlohmann::json::parse(renderBatchJson(sampleEntries()));
    EXPECT_EQ(json["schema"], "sectoryn-batch");
    ASSERT_EQ(json["jobs"].size(), 3U);
    EXPECT_EQ(json["jobs"][0]["outcome"], "suspicious_indicators");
    EXPECT_EQ(json["jobs"][1]["duplicate_of"], 1);
    EXPECT_TRUE(json["jobs"][1]["score"].is_null());
    EXPECT_TRUE(json["jobs"][2]["sha256"].is_null());
    EXPECT_EQ(json["jobs"][2]["state"], "failed");
}

TEST(BatchExport, WritesReportsNamedByHash) {
    const test::TempDir dir;
    Result<AnalysisEngine> engine = AnalysisEngine::createDefault();
    ASSERT_TRUE(engine.hasValue());
    const auto file = dir.write(
        "sample.exe",
        test::PeBuilder().addSection(".text", test::PeBuilder::kCode, test::bytesOf("x")).build());
    const Result<AnalysisResult> result = engine.value().analyze(file);
    ASSERT_TRUE(result.hasValue());

    const auto out = dir.path() / "reports";
    std::filesystem::create_directory(out);
    constexpr std::array formats = {ReportFormat::Json, ReportFormat::Html};
    const Result<std::vector<std::filesystem::path>> written =
        writeReports(out, result.value(), formats);
    ASSERT_TRUE(written.hasValue()) << written.error().describe();
    ASSERT_EQ(written.value().size(), 2U);
    EXPECT_EQ(written.value()[0].filename().string(), result.value().sha256 + ".report.json");
    EXPECT_EQ(written.value()[1].filename().string(), result.value().sha256 + ".report.html");
    for (const auto& path : written.value()) {
        EXPECT_GT(std::filesystem::file_size(path), 0U);
    }
}

TEST(BatchExport, RefusesResultsWithoutHash) {
    const test::TempDir dir;
    AnalysisResult result;
    result.sha256 = "../../escape";
    constexpr std::array formats = {ReportFormat::Json};
    const auto written = writeReports(dir.path(), result, formats);
    ASSERT_FALSE(written.hasValue());
    EXPECT_EQ(written.error().code, ErrorCode::InvalidInput);
}

} // namespace
} // namespace sectoryn
