#pragma once

#include "core/CancellationToken.hpp"
#include "core/Limits.hpp"
#include "core/Result.hpp"
#include "parsers/PeModel.hpp"

#include <cstddef>
#include <span>
#include <string>

namespace sectoryn {

class IPeParser {
public:
    virtual ~IPeParser() = default;

    // `data` is the complete file. Implementations must not keep references to it after
    // returning. A returned image may still carry issues and per-structure failures.
    [[nodiscard]] virtual Result<PeImage> parse(std::span<const std::byte> data,
                                                const AnalysisLimits& limits,
                                                const CancellationToken& token) const = 0;

    // Name and version of the underlying parser, recorded in reports.
    [[nodiscard]] virtual std::string name() const = 0;
    [[nodiscard]] virtual std::string version() const = 0;

protected:
    IPeParser() = default;
    IPeParser(const IPeParser&) = default;
    IPeParser& operator=(const IPeParser&) = default;
    IPeParser(IPeParser&&) = default;
    IPeParser& operator=(IPeParser&&) = default;
};

} // namespace sectoryn
