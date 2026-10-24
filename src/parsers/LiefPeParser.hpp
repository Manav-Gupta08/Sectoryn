#pragma once

#include "parsers/IPeParser.hpp"

namespace sectoryn {

// PE parser backed by LIEF. LIEF reads the structures; this class copies them into PeImage,
// records which ones could not be read, and adds Sectoryn's own consistency checks.
class LiefPeParser final : public IPeParser {
public:
    [[nodiscard]] Result<PeImage> parse(std::span<const std::byte> data,
                                        const AnalysisLimits& limits,
                                        const CancellationToken& token) const override;

    [[nodiscard]] std::string name() const override;
    [[nodiscard]] std::string version() const override;
};

} // namespace sectoryn
