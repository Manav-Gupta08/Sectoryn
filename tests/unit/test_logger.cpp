#include "core/Logger.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <sstream>
#include <string>

namespace sectoryn {
namespace {

TEST(Logger, FiltersBelowThreshold) {
    std::ostringstream out;
    Logger logger(LogLevel::Warning, &out);
    logger.info("hidden");
    logger.warning("shown");
    const std::string text = out.str();
    EXPECT_EQ(text.find("hidden"), std::string::npos);
    EXPECT_NE(text.find("[WARN] shown"), std::string::npos);
}

TEST(Logger, OffDisablesOutput) {
    std::ostringstream out;
    Logger logger(LogLevel::Off, &out);
    logger.error("nothing");
    EXPECT_TRUE(out.str().empty());
}

TEST(Logger, SanitizeReplacesControlCharacters) {
    EXPECT_EQ(Logger::sanitize("a\nb\rc\x1b"), "a?b?c?");
    EXPECT_EQ(Logger::sanitize("tab\tkept"), "tab\tkept");
}

TEST(Logger, SanitizeTruncatesLongMessages) {
    const std::string longMessage(Logger::kMaxMessageBytes + 100, 'x');
    const std::string sanitized = Logger::sanitize(longMessage);
    EXPECT_LT(sanitized.size(), longMessage.size());
    EXPECT_TRUE(sanitized.ends_with("...[truncated]"));
}

TEST(Logger, RejectsInvalidFileSettings) {
    Logger logger;
    EXPECT_FALSE(logger.openFile({}, 1024).hasValue());
    EXPECT_FALSE(logger.openFile("unused.log", 0).hasValue());
}

TEST(Logger, RotatesFileWhenLimitExceeded) {
    const std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "sectoryn_logger_rotation_test";
    std::filesystem::remove_all(dir);
    const std::filesystem::path path = dir / "test.log";

    constexpr std::uintmax_t kLimit = 256;
    {
        Logger logger(LogLevel::Debug);
        ASSERT_TRUE(logger.openFile(path, kLimit).hasValue());
        for (int i = 0; i < 20; ++i) {
            logger.info("rotation test line with some padding text");
        }
    }

    std::filesystem::path backup = path;
    backup += ".1";
    EXPECT_TRUE(std::filesystem::exists(backup));
    EXPECT_LE(std::filesystem::file_size(path), kLimit);
    EXPECT_LE(std::filesystem::file_size(backup), kLimit);
    std::filesystem::remove_all(dir);
}

} // namespace
} // namespace sectoryn
