#include "core/Config.hpp"
#include "support/TempDir.hpp"

#include <gtest/gtest.h>

#include <string>

namespace sectoryn {
namespace {

TEST(Config, EmptyTextYieldsDefaults) {
    const Result<Config> config = parseConfig("");
    ASSERT_TRUE(config.hasValue()) << config.error().describe();
    EXPECT_EQ(config.value().limits.maxFileBytes, AnalysisLimits{}.maxFileBytes);
    EXPECT_EQ(config.value().workerCount, Config{}.workerCount);
}

TEST(Config, DefaultsAreValid) {
    EXPECT_TRUE(validate(Config{}).hasValue());
}

TEST(Config, ParsesKnownKeys) {
    const Result<Config> config = parseConfig("\xEF\xBB\xBF# comment\n"
                                              "max_file_bytes = 1048576\r\n"
                                              "\n"
                                              "  worker_count=4  \n"
                                              "max_queued_jobs = 10\n"
                                              "min_string_length = 4\n"
                                              "log_level = debug");
    ASSERT_TRUE(config.hasValue()) << config.error().describe();
    EXPECT_EQ(config.value().limits.maxFileBytes, 1048576U);
    EXPECT_EQ(config.value().workerCount, 4U);
    EXPECT_EQ(config.value().maxQueuedJobs, 10U);
    EXPECT_EQ(config.value().limits.minStringLength, 4U);
    EXPECT_EQ(config.value().logLevel, LogLevel::Debug);
}

TEST(Config, RejectsUnknownKey) {
    const Result<Config> config = parseConfig("max_file_bytes = 10\nmax_fiel_bytes = 10\n");
    ASSERT_FALSE(config.hasValue());
    EXPECT_EQ(config.error().code, ErrorCode::InvalidInput);
    EXPECT_NE(config.error().message.find("line 2"), std::string::npos);
    EXPECT_NE(config.error().message.find("max_fiel_bytes"), std::string::npos);
}

TEST(Config, RejectsDuplicateKey) {
    const Result<Config> config = parseConfig("worker_count = 1\nworker_count = 2\n");
    ASSERT_FALSE(config.hasValue());
    EXPECT_NE(config.error().message.find("duplicate"), std::string::npos);
}

TEST(Config, RejectsMalformedLines) {
    EXPECT_FALSE(parseConfig("worker_count\n").hasValue());
    EXPECT_FALSE(parseConfig("= 4\n").hasValue());
    EXPECT_FALSE(parseConfig("worker_count =\n").hasValue());
}

TEST(Config, RejectsInvalidNumbers) {
    EXPECT_FALSE(parseConfig("worker_count = -1").hasValue());
    EXPECT_FALSE(parseConfig("worker_count = 4x").hasValue());
    EXPECT_FALSE(parseConfig("worker_count = 0x4").hasValue());
    EXPECT_FALSE(parseConfig("max_file_bytes = 99999999999999999999999").hasValue());
}

TEST(Config, RejectsUnknownLogLevel) {
    EXPECT_FALSE(parseConfig("log_level = verbose").hasValue());
    EXPECT_FALSE(parseConfig("log_level = DEBUG").hasValue());
}

TEST(Config, RejectsValuesOutsideCeilings) {
    EXPECT_FALSE(parseConfig("worker_count = 0").hasValue());
    EXPECT_FALSE(parseConfig("worker_count = 65").hasValue());
    EXPECT_FALSE(parseConfig("max_file_bytes = 0").hasValue());
    EXPECT_FALSE(parseConfig("read_chunk_bytes = 16").hasValue());
    EXPECT_FALSE(parseConfig("max_queued_jobs = 0").hasValue());
}

TEST(Config, RejectsInconsistentStringLengths) {
    const Result<Config> config = parseConfig("min_string_length = 100\nmax_string_length = 50");
    ASSERT_FALSE(config.hasValue());
    EXPECT_NE(config.error().message.find("min_string_length"), std::string::npos);
}

TEST(Config, LoadsFromFile) {
    const test::TempDir dir;
    const auto path = dir.write("sectoryn.conf", "worker_count = 3\n");
    const Result<Config> config = loadConfig(path);
    ASSERT_TRUE(config.hasValue()) << config.error().describe();
    EXPECT_EQ(config.value().workerCount, 3U);
}

TEST(Config, LoadReportsMissingFile) {
    const test::TempDir dir;
    const Result<Config> config = loadConfig(dir.path() / "missing.conf");
    ASSERT_FALSE(config.hasValue());
    EXPECT_EQ(config.error().code, ErrorCode::IoFailure);
}

TEST(Config, LoadRejectsOversizedFile) {
    const test::TempDir dir;
    const std::string text(Config::kMaxFileBytes + 1, '#');
    const Result<Config> config = loadConfig(dir.write("big.conf", text));
    ASSERT_FALSE(config.hasValue());
    EXPECT_EQ(config.error().code, ErrorCode::ResourceLimitExceeded);
}

TEST(Config, FormattedTextParsesBackUnchanged) {
    Config config;
    config.limits.maxFileBytes = 64 * kMiB;
    config.limits.minStringLength = 8;
    config.workerCount = 6;
    config.logLevel = LogLevel::Warning;
    ASSERT_TRUE(validate(config).hasValue());

    const std::string text = formatConfig(config);
    EXPECT_NE(text.find("log_level = warning\n"), std::string::npos);
    EXPECT_NE(text.find("max_file_bytes = 67108864\n"), std::string::npos);

    const Result<Config> parsed = parseConfig(text);
    ASSERT_TRUE(parsed.hasValue()) << parsed.error().describe();
    EXPECT_EQ(parsed.value(), config);
}

TEST(Config, StoresYaraRulesDirectoryAsUtf8) {
    EXPECT_EQ(formatConfig(Config{}).find("yara_rules_directory"), std::string::npos);

    Config config;
    config.yaraRulesDirectory = std::filesystem::path(u8"rules/r\u00e8gles yara");
    const std::string text = formatConfig(config);
    EXPECT_NE(text.find("yara_rules_directory = rules/r\xC3\xA8gles yara\n"), std::string::npos);
    const Result<Config> parsed = parseConfig(text);
    ASSERT_TRUE(parsed.hasValue()) << parsed.error().describe();
    EXPECT_EQ(parsed.value().yaraRulesDirectory, config.yaraRulesDirectory);
}

TEST(Config, FormatsEveryLogLevel) {
    for (const LogLevel level :
         {LogLevel::Debug, LogLevel::Info, LogLevel::Warning, LogLevel::Error, LogLevel::Off}) {
        Config config;
        config.logLevel = level;
        const Result<Config> parsed = parseConfig(formatConfig(config));
        ASSERT_TRUE(parsed.hasValue());
        EXPECT_EQ(parsed.value().logLevel, level);
    }
}

} // namespace
} // namespace sectoryn
