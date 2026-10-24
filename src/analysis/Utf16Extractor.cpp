#include "analysis/StringExtractor.hpp"

namespace sectoryn {

// Each code unit is formed from the previous byte (low) and the current one (high), so a
// unit can start at any offset. Runs at even and odd offsets never share a code unit.
void StringExtractor::feedUtf16(std::span<const std::byte> chunk) {
    std::uint64_t offset = position_;
    for (const std::byte high : chunk) {
        if (previousByte_) {
            const std::uint64_t unitOffset = offset - 1;
            Run& run = utf16_[unitOffset & 1U];
            const auto low = std::to_integer<std::uint8_t>(*previousByte_);
            if (std::to_integer<std::uint8_t>(high) == 0 && isPrintableAscii(low)) {
                append(run, unitOffset, static_cast<char>(low));
            } else {
                close(run, StringEncoding::Utf16Le);
            }
        }
        previousByte_ = high;
        ++offset;
    }
}

} // namespace sectoryn
