#include "analysis/EntropyAnalyzer.hpp"

#include "utilities/FileReader.hpp"

#include <utility>

namespace sectoryn {

namespace {

Result<RangeEntropy> measure(FileReader& reader, ByteRange range, const AnalysisLimits& limits,
                             const CancellationToken& token) {
    if (range.empty()) {
        return RangeEntropy{};
    }
    ByteStatistics statistics;
    Status status = reader.forEachChunk(range, limits.readChunkBytes, token,
                                        [&statistics](std::span<const std::byte> chunk) {
                                            statistics.add(chunk);
                                            return Status{};
                                        });
    if (!status) {
        return std::move(status).error();
    }
    return RangeEntropy{statistics.entropy(), statistics.total()};
}

} // namespace

Result<EntropyReport> analyzeEntropy(FileReader& reader, const SectionAnalysis& sections,
                                     const Overlay& overlay, const AnalysisLimits& limits,
                                     const CancellationToken& token) {
    EntropyReport report;
    EntropyProfile profile(reader.size());
    Status scanned = reader.forEachChunk({0, reader.size()}, limits.readChunkBytes, token,
                                         [&](std::span<const std::byte> chunk) {
                                             report.file.add(chunk);
                                             profile.add(chunk);
                                             return Status{};
                                         });
    if (!scanned) {
        return std::move(scanned).error();
    }
    report.profileBlockSize = profile.blockSize();
    report.profile = profile.finish();

    std::uint64_t budget = reader.size() * EntropyReport::kSectionReadFactor;
    report.sections.reserve(sections.sections.size());
    for (const SectionAssessment& section : sections.sections) {
        const ByteRange range = section.readableRange;
        if (range.size > budget) {
            report.sectionBudgetExhausted = true;
            report.sections.push_back({std::nullopt, range.size});
            continue;
        }
        budget -= range.size;
        Result<RangeEntropy> measured = measure(reader, range, limits, token);
        if (!measured) {
            return std::move(measured).error();
        }
        report.sections.push_back(measured.value());
    }

    if (overlay.status.state == FieldState::Present) {
        Result<RangeEntropy> measured =
            measure(reader, {overlay.fileOffset, overlay.size}, limits, token);
        if (!measured) {
            return std::move(measured).error();
        }
        report.overlay = measured.value();
    }
    return report;
}

} // namespace sectoryn
