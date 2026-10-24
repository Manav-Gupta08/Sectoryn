#pragma once

#include "analysis/StringExtractor.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {

enum class IndicatorKind : std::uint8_t {
    Url,
    Domain,
    IpV4Address,
    FilePath,
    UncPath,
    RegistryKey,
    PowerShell,
    CommandLine,
    Persistence,
    EncodedData,
};

[[nodiscard]] std::string_view toString(IndicatorKind kind) noexcept;

// Something in a string that is worth an analyst's attention. Indicators are raw observations
// for detection rules; on their own they do not mean the file does anything harmful.
struct Indicator {
    IndicatorKind kind;
    // The matched text, e.g. the full URL or the keyword that was found.
    std::string value;
    // Index into StringExtraction::strings.
    std::size_t stringIndex = 0;
    // File offset from classifyStrings; character position within the text from classifyString.
    std::uint64_t offset = 0;

    friend bool operator==(const Indicator&, const Indicator&) = default;
};

// Scans one string. Matching is literal, case-insensitive where Windows is, and uses no
// regular expressions, so hostile input cannot trigger backtracking blow-ups.
[[nodiscard]] std::vector<Indicator> classifyString(std::string_view text);

[[nodiscard]] std::vector<Indicator> classifyStrings(const StringExtraction& extraction);

} // namespace sectoryn
