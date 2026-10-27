#include "reputation/IReputationProvider.hpp"

#include <algorithm>
#include <cctype>

namespace sectoryn {

bool isSha256Hex(std::string_view text) noexcept {
    return text.size() == 64 && std::ranges::all_of(text, [](char c) {
               return std::isxdigit(static_cast<unsigned char>(c)) != 0;
           });
}

} // namespace sectoryn
