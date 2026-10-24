#include "analysis/StringExtractor.hpp"

#include "utilities/FileReader.hpp"

#include <algorithm>
#include <utility>

namespace sectoryn {

std::string_view toString(StringEncoding encoding) noexcept {
    switch (encoding) {
    case StringEncoding::Ascii:
        return "ASCII";
    case StringEncoding::Utf16Le:
        return "UTF-16LE";
    }
    return "unknown";
}

bool isPrintableAscii(std::uint8_t byte) noexcept {
    return (byte >= 0x20 && byte < 0x7F) || byte == '\t';
}

StringExtractor::StringExtractor(const AnalysisLimits& limits)
    : minLength_(limits.minStringLength)
    , maxLength_(limits.maxStringLength)
    , stringsLeft_(limits.maxStrings)
    , bytesLeft_(limits.maxStringBytes) {}

bool StringExtractor::feed(std::span<const std::byte> chunk) {
    if (limitReached_) {
        return false;
    }
    feedAscii(chunk);
    feedUtf16(chunk);
    position_ += chunk.size();
    return !limitReached_;
}

StringExtraction StringExtractor::finish() {
    close(ascii_, StringEncoding::Ascii);
    close(utf16_[0], StringEncoding::Utf16Le);
    close(utf16_[1], StringEncoding::Utf16Le);

    std::ranges::stable_sort(strings_, [](const ExtractedString& a, const ExtractedString& b) {
        return a.offset != b.offset ? a.offset < b.offset : a.encoding < b.encoding;
    });
    return {std::exchange(strings_, {}), limitReached_};
}

void StringExtractor::feedAscii(std::span<const std::byte> chunk) {
    std::uint64_t offset = position_;
    for (const std::byte b : chunk) {
        const auto value = std::to_integer<std::uint8_t>(b);
        if (isPrintableAscii(value)) {
            append(ascii_, offset, static_cast<char>(value));
        } else {
            close(ascii_, StringEncoding::Ascii);
        }
        ++offset;
    }
}

void StringExtractor::append(Run& run, std::uint64_t offset, char c) const {
    if (run.length == 0) {
        run.start = offset;
    }
    ++run.length;
    if (run.text.size() < maxLength_) {
        run.text.push_back(c);
    }
}

void StringExtractor::close(Run& run, StringEncoding encoding) {
    if (run.length >= minLength_ && !limitReached_) {
        if (stringsLeft_ == 0 || run.text.size() > bytesLeft_) {
            limitReached_ = true;
        } else {
            --stringsLeft_;
            bytesLeft_ -= run.text.size();
            strings_.push_back({run.start, encoding, std::move(run.text), run.length > maxLength_});
        }
    }
    run.length = 0;
    run.text.clear();
}

Result<StringExtraction> extractStrings(FileReader& reader, const AnalysisLimits& limits,
                                        const CancellationToken& token) {
    StringExtractor extractor(limits);
    Status scanned = reader.forEachChunk(
        {0, reader.size()}, limits.readChunkBytes, token,
        [&extractor](std::span<const std::byte> chunk) -> Status {
            if (!extractor.feed(chunk)) {
                return Error{ErrorCode::ResourceLimitExceeded, "string limit reached"};
            }
            return {};
        });
    // Hitting a string limit ends the scan early but still yields a usable, flagged result.
    if (!scanned && scanned.error().code != ErrorCode::ResourceLimitExceeded) {
        return std::move(scanned).error();
    }
    return extractor.finish();
}

} // namespace sectoryn
