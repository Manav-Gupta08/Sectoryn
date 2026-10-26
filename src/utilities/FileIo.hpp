#pragma once

#include "core/Result.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace sectoryn {

// Reads a whole file that is expected to be small, such as a rule or history file. Files larger
// than `maxBytes` are refused; the size is checked while reading, not taken from the directory.
[[nodiscard]] Result<std::string> readSmallFile(const std::filesystem::path& path,
                                                std::size_t maxBytes);

// Replaces `path` with `contents` so that readers see either the old file or the complete new
// one, never a partial write. The data goes to a temporary file in the same directory first.
[[nodiscard]] Status writeFileAtomically(const std::filesystem::path& path,
                                         std::string_view contents);

} // namespace sectoryn
