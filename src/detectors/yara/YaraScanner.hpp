#pragma once

#include "core/CancellationToken.hpp"
#include "core/Result.hpp"
#include "detectors/yara/YaraCompiler.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace sectoryn {

struct YaraStringMatch {
    std::string identifier{};
    std::uint64_t offset = 0;
    std::uint32_t length = 0;
};

struct YaraMetadata {
    std::string name{};
    std::string value{};
};

struct YaraMatch {
    std::string rule{};
    std::string ruleNamespace{};
    std::vector<std::string> tags{};
    std::vector<YaraMetadata> metadata{};
    std::vector<YaraStringMatch> strings{};
    // More string matches than kMaxStringMatches were found; the first ones are listed.
    bool stringsTruncated = false;
};

struct YaraScanOptions {
    std::chrono::seconds timeout{60};
};

struct YaraScanResult {
    std::vector<YaraMatch> matches{};
    // More rules than kMaxMatchingRules matched; the first ones are listed.
    bool matchesTruncated = false;
    // libyara stopped recording matches of some string because it matched too often.
    bool tooManyMatches = false;

    static constexpr std::size_t kMaxMatchingRules = 500;
    static constexpr std::size_t kMaxStringMatches = 25;
};

// Scans a file with compiled rules. The file is opened read-only by this function and handed to
// libyara as a handle, so paths in any encoding work. Cancellation is checked whenever libyara
// reports progress; the timeout bounds the time spent between reports.
[[nodiscard]] Result<YaraScanResult> scanFileWithYara(const YaraRuleSet& rules,
                                                      const std::filesystem::path& path,
                                                      const CancellationToken& token,
                                                      const YaraScanOptions& options = {});

} // namespace sectoryn
