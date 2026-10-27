#include "analysis/SectionAnalyzer.hpp"
#include "parsers/LiefPeParser.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace {

// Small limits keep each iteration fast while still exercising every limit check.
sectoryn::AnalysisLimits fuzzLimits() {
    sectoryn::AnalysisLimits limits;
    limits.maxFileBytes = 4 * sectoryn::kMiB;
    limits.maxSections = 96;
    limits.maxImportedModules = 64;
    limits.maxImportedFunctions = 1024;
    limits.maxExports = 1024;
    limits.maxResourceEntries = 256;
    return limits;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const sectoryn::LiefPeParser parser;
    static const sectoryn::AnalysisLimits limits = fuzzLimits();
    if (size > limits.maxFileBytes) {
        return 0;
    }
    const std::span<const std::byte> bytes(reinterpret_cast<const std::byte*>(data), size);
    const sectoryn::Result<sectoryn::PeImage> image = parser.parse(bytes, limits, {});
    if (image) {
        // Section analysis consumes parser output without further validation by the parser.
        static_cast<void>(sectoryn::analyzeSections(image.value()));
    }
    return 0;
}
