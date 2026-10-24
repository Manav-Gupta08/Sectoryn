#include "core/Config.hpp"

#include <array>
#include <charconv>
#include <concepts>
#include <format>
#include <fstream>
#include <string>
#include <system_error>

namespace sectoryn {

namespace {

constexpr std::size_t kMaxKeyLengthInMessages = 64;

std::string_view trim(std::string_view text) {
    constexpr std::string_view kWhitespace = " \t\r";
    const std::size_t first = text.find_first_not_of(kWhitespace);
    if (first == std::string_view::npos) {
        return {};
    }
    const std::size_t last = text.find_last_not_of(kWhitespace);
    return text.substr(first, last - first + 1);
}

template <std::unsigned_integral T>
Status parseUnsigned(std::string_view text, T& out) {
    T value{};
    const char* const end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(text.data(), end, value);
    if (ec == std::errc::result_out_of_range) {
        return Error{ErrorCode::InvalidInput, "value is too large"};
    }
    if (ec != std::errc{} || ptr != end) {
        return Error{ErrorCode::InvalidInput, "expected a non-negative integer"};
    }
    out = value;
    return {};
}

constexpr std::array kLogLevels = {LogLevel::Debug, LogLevel::Info, LogLevel::Warning,
                                   LogLevel::Error, LogLevel::Off};
constexpr std::array<std::string_view, kLogLevels.size()> kLogLevelNames = {
    "debug", "info", "warning", "error", "off"};

Status parseLogLevel(std::string_view text, LogLevel& out) {
    for (std::size_t i = 0; i < kLogLevels.size(); ++i) {
        if (text == kLogLevelNames[i]) {
            out = kLogLevels[i];
            return {};
        }
    }
    return Error{ErrorCode::InvalidInput, "expected one of debug, info, warning, error, off"};
}

std::string formatLogLevel(LogLevel level) {
    for (std::size_t i = 0; i < kLogLevels.size(); ++i) {
        if (level == kLogLevels[i]) {
            return std::string(kLogLevelNames[i]);
        }
    }
    return "info";
}

Status parsePath(std::string_view text, std::filesystem::path& out) {
    out = std::filesystem::path(std::u8string(text.begin(), text.end()));
    return {};
}

std::string formatPath(const std::filesystem::path& path) {
    const std::u8string text = path.u8string();
    return {text.begin(), text.end()};
}

// One entry per key, used both to parse and to write configuration files, so every key that can
// be read is also written.
struct KeyHandler {
    std::string_view key;
    Status (*apply)(Config&, std::string_view);
    std::string (*format)(const Config&);
};

using V = std::string_view;
using C = const Config&;

constexpr std::array kHandlers = {
    KeyHandler{"max_file_bytes",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxFileBytes); },
               [](C c) { return std::to_string(c.limits.maxFileBytes); }},
    KeyHandler{"read_chunk_bytes",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.readChunkBytes); },
               [](C c) { return std::to_string(c.limits.readChunkBytes); }},
    KeyHandler{"max_sections",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxSections); },
               [](C c) { return std::to_string(c.limits.maxSections); }},
    KeyHandler{"max_imported_modules",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxImportedModules); },
               [](C c) { return std::to_string(c.limits.maxImportedModules); }},
    KeyHandler{"max_imported_functions",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxImportedFunctions); },
               [](C c) { return std::to_string(c.limits.maxImportedFunctions); }},
    KeyHandler{"max_exports",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxExports); },
               [](C c) { return std::to_string(c.limits.maxExports); }},
    KeyHandler{"max_resource_entries",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxResourceEntries); },
               [](C c) { return std::to_string(c.limits.maxResourceEntries); }},
    KeyHandler{"max_strings",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxStrings); },
               [](C c) { return std::to_string(c.limits.maxStrings); }},
    KeyHandler{"max_string_bytes",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxStringBytes); },
               [](C c) { return std::to_string(c.limits.maxStringBytes); }},
    KeyHandler{"min_string_length",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.minStringLength); },
               [](C c) { return std::to_string(c.limits.minStringLength); }},
    KeyHandler{"max_string_length",
               [](Config& c, V v) { return parseUnsigned(v, c.limits.maxStringLength); },
               [](C c) { return std::to_string(c.limits.maxStringLength); }},
    KeyHandler{"worker_count", [](Config& c, V v) { return parseUnsigned(v, c.workerCount); },
               [](C c) { return std::to_string(c.workerCount); }},
    KeyHandler{"max_queued_jobs", [](Config& c, V v) { return parseUnsigned(v, c.maxQueuedJobs); },
               [](C c) { return std::to_string(c.maxQueuedJobs); }},
    KeyHandler{"log_level", [](Config& c, V v) { return parseLogLevel(v, c.logLevel); },
               [](C c) { return formatLogLevel(c.logLevel); }},
    KeyHandler{"yara_rules_directory",
               [](Config& c, V v) { return parsePath(v, c.yaraRulesDirectory); },
               [](C c) { return formatPath(c.yaraRulesDirectory); }},
};

Error lineError(std::size_t lineNumber, std::string_view detail) {
    return Error{ErrorCode::InvalidInput, std::format("line {}: {}", lineNumber, detail)};
}

} // namespace

Status validate(const Config& config) {
    if (Status status = validate(config.limits); !status) {
        return status;
    }
    if (config.workerCount == 0 || config.workerCount > Config::kMaxWorkerCount) {
        return Error{ErrorCode::InvalidInput,
                     std::format("worker_count must be between 1 and {}", Config::kMaxWorkerCount)};
    }
    if (config.maxQueuedJobs == 0 || config.maxQueuedJobs > Config::kMaxQueuedJobsCeiling) {
        return Error{ErrorCode::InvalidInput,
                     std::format("max_queued_jobs must be between 1 and {}",
                                 Config::kMaxQueuedJobsCeiling)};
    }
    return {};
}

Result<Config> parseConfig(std::string_view text) {
    constexpr std::string_view kUtf8Bom = "\xEF\xBB\xBF";
    if (text.starts_with(kUtf8Bom)) {
        text.remove_prefix(kUtf8Bom.size());
    }

    Config config;
    std::array<bool, kHandlers.size()> seen{};
    std::size_t lineNumber = 0;

    while (!text.empty()) {
        ++lineNumber;
        const std::size_t newline = text.find('\n');
        const std::string_view rawLine = text.substr(0, newline);
        text.remove_prefix(newline == std::string_view::npos ? text.size() : newline + 1);

        const std::string_view line = trim(rawLine);
        if (line.empty() || line.front() == '#') {
            continue;
        }

        const std::size_t equals = line.find('=');
        if (equals == std::string_view::npos) {
            return lineError(lineNumber, "expected 'key = value'");
        }
        const std::string_view key = trim(line.substr(0, equals));
        const std::string_view value = trim(line.substr(equals + 1));
        if (key.empty() || value.empty()) {
            return lineError(lineNumber, "expected 'key = value'");
        }

        std::size_t index = 0;
        while (index < kHandlers.size() && kHandlers[index].key != key) {
            ++index;
        }
        if (index == kHandlers.size()) {
            const std::string_view shownKey = key.substr(0, kMaxKeyLengthInMessages);
            return lineError(lineNumber, std::format("unknown key '{}'", shownKey));
        }
        if (seen[index]) {
            return lineError(lineNumber, std::format("duplicate key '{}'", key));
        }
        seen[index] = true;

        if (Status status = kHandlers[index].apply(config, value); !status) {
            return lineError(lineNumber, std::format("{}: {}", key, status.error().message));
        }
    }

    if (Status status = validate(config); !status) {
        return std::move(status).error();
    }
    return config;
}

std::string formatConfig(const Config& config) {
    std::string text = "# Sectoryn configuration. Lines are 'key = value'; unknown keys are "
                       "rejected.\n";
    for (const KeyHandler& handler : kHandlers) {
        // Keys without a value, such as an unset folder, are left out; the parser needs a value.
        if (const std::string value = handler.format(config); !value.empty()) {
            text += std::format("{} = {}\n", handler.key, value);
        }
    }
    return text;
}

Result<Config> loadConfig(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        return Error{ErrorCode::IoFailure, "cannot open configuration file"};
    }

    // Read one byte past the limit so an oversized file is detected without trusting stat().
    std::string text(Config::kMaxFileBytes + 1, '\0');
    in.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (in.bad()) {
        return Error{ErrorCode::IoFailure, "cannot read configuration file"};
    }
    const auto bytesRead = static_cast<std::size_t>(in.gcount());
    if (bytesRead > Config::kMaxFileBytes) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("configuration file exceeds {} bytes", Config::kMaxFileBytes)};
    }
    text.resize(bytesRead);
    return parseConfig(text);
}

} // namespace sectoryn
