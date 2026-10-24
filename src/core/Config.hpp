#pragma once

#include "core/Limits.hpp"
#include "core/Logger.hpp"
#include "core/Result.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace sectoryn {

struct Config {
    static constexpr std::size_t kMaxWorkerCount = 64;
    static constexpr std::size_t kMaxQueuedJobsCeiling = 100000;
    // Configuration files are small; anything larger is rejected rather than parsed.
    static constexpr std::size_t kMaxFileBytes = 64 * 1024;

    AnalysisLimits limits;
    std::size_t workerCount = 2;
    std::size_t maxQueuedJobs = 256;
    LogLevel logLevel = LogLevel::Info;
    // Folder with .yar and .yara files; empty disables YARA scanning.
    std::filesystem::path yaraRulesDirectory;

    friend bool operator==(const Config&, const Config&) = default;
};

[[nodiscard]] Status validate(const Config& config);

// Parses "key = value" lines. Blank lines and lines starting with '#' are ignored. Unknown
// or repeated keys are errors so that typos do not silently fall back to defaults.
[[nodiscard]] Result<Config> parseConfig(std::string_view text);

// Writes every key, so parseConfig(formatConfig(config)) == config for any valid config.
[[nodiscard]] std::string formatConfig(const Config& config);

[[nodiscard]] Result<Config> loadConfig(const std::filesystem::path& path);

} // namespace sectoryn
