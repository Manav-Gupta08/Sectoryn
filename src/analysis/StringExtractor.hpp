#pragma once

#include "core/CancellationToken.hpp"
#include "core/Limits.hpp"
#include "core/Result.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {

class FileReader;

enum class StringEncoding : std::uint8_t { Ascii, Utf16Le };

[[nodiscard]] std::string_view toString(StringEncoding encoding) noexcept;

struct ExtractedString {
    std::uint64_t offset = 0;
    StringEncoding encoding = StringEncoding::Ascii;
    // Printable ASCII and tab only. UTF-16 strings are limited to the same range.
    std::string text;
    // The run was longer than maxStringLength; text holds its beginning.
    bool truncated = false;

    friend bool operator==(const ExtractedString&, const ExtractedString&) = default;
};

struct StringExtraction {
    // Ordered by offset, ASCII before UTF-16 at equal offsets.
    std::vector<ExtractedString> strings;
    // maxStrings or maxStringBytes was reached; the file was not scanned to the end.
    bool limitReached = false;
};

// Finds runs of printable ASCII and UTF-16LE text. Input is fed in file order, in chunks of
// any size; runs that span chunk boundaries are joined.
class StringExtractor {
public:
    explicit StringExtractor(const AnalysisLimits& limits);

    // Returns false once a limit has been reached. Further input is then ignored.
    bool feed(std::span<const std::byte> chunk);

    [[nodiscard]] StringExtraction finish();

private:
    struct Run {
        std::uint64_t start = 0;
        std::size_t length = 0;
        std::string text;
    };

    void feedAscii(std::span<const std::byte> chunk);
    void feedUtf16(std::span<const std::byte> chunk);
    void append(Run& run, std::uint64_t offset, char c) const;
    void close(Run& run, StringEncoding encoding);

    std::size_t minLength_;
    std::size_t maxLength_;
    std::size_t stringsLeft_;
    std::size_t bytesLeft_;
    bool limitReached_ = false;

    std::uint64_t position_ = 0;
    Run ascii_;
    // UTF-16 runs can start at even or odd offsets; each parity is tracked separately.
    std::array<Run, 2> utf16_;
    std::optional<std::byte> previousByte_;
    std::vector<ExtractedString> strings_;
};

[[nodiscard]] bool isPrintableAscii(std::uint8_t byte) noexcept;

// Streams the whole file through a StringExtractor.
[[nodiscard]] Result<StringExtraction> extractStrings(FileReader& reader,
                                                      const AnalysisLimits& limits,
                                                      const CancellationToken& token);

} // namespace sectoryn
