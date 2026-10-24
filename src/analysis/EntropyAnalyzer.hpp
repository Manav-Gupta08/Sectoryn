#pragma once

#include "analysis/ByteStatistics.hpp"
#include "analysis/EntropyProfile.hpp"
#include "analysis/SectionAnalyzer.hpp"
#include "core/CancellationToken.hpp"
#include "core/Limits.hpp"
#include "core/Result.hpp"
#include "parsers/PeModel.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace sectoryn {

class FileReader;

struct RangeEntropy {
    // Unset when the range has no bytes in the file or was skipped to stay within budget.
    std::optional<double> entropy;
    std::uint64_t bytes = 0;
};

struct EntropyReport {
    ByteStatistics file;
    std::vector<EntropyPoint> profile;
    std::uint64_t profileBlockSize = 0;
    // Parallel to SectionAnalysis::sections; computed over each section's readable range.
    std::vector<RangeEntropy> sections;
    RangeEntropy overlay;
    // Some sections were skipped because overlapping sections would have meant re-reading the
    // file many times over.
    bool sectionBudgetExhausted = false;

    // Section ranges read in total may not exceed this multiple of the file size.
    static constexpr std::uint64_t kSectionReadFactor = 2;
};

// One pass over the whole file for its statistics and profile, then one read per section.
[[nodiscard]] Result<EntropyReport> analyzeEntropy(FileReader& reader,
                                                   const SectionAnalysis& sections,
                                                   const Overlay& overlay,
                                                   const AnalysisLimits& limits,
                                                   const CancellationToken& token);

} // namespace sectoryn
