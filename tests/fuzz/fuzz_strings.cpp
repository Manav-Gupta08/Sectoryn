#include "analysis/IndicatorClassifier.hpp"
#include "analysis/StringExtractor.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) {
        return 0;
    }
    sectoryn::AnalysisLimits limits;
    limits.maxStrings = 4096;
    limits.maxStringBytes = 1024 * 1024;
    // The first byte picks the minimum length and the chunk size, so runs that cross chunk
    // boundaries are exercised as well.
    limits.minStringLength = 2 + std::size_t{data[0]} % 16;
    const std::size_t chunk = 1 + std::size_t{data[0]} % 61;

    const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data) + 1, size - 1);
    sectoryn::StringExtractor extractor(limits);
    for (std::size_t offset = 0; offset < bytes.size(); offset += chunk) {
        if (!extractor.feed(bytes.subspan(offset, std::min(chunk, bytes.size() - offset)))) {
            break;
        }
    }
    const sectoryn::StringExtraction extraction = extractor.finish();
    static_cast<void>(sectoryn::classifyStrings(extraction));
    return 0;
}
