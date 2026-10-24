#include "core/Limits.hpp"

#include <format>
#include <string_view>

namespace sectoryn {

namespace {

Status checkRange(std::string_view name, std::uint64_t value, std::uint64_t min,
                  std::uint64_t max) {
    if (value < min || value > max) {
        return Error{ErrorCode::InvalidInput,
                     std::format("{} must be between {} and {}, got {}", name, min, max, value)};
    }
    return {};
}

} // namespace

Status validate(const AnalysisLimits& limits) {
    using C = LimitCeilings;
    const struct {
        std::string_view name;
        std::uint64_t value;
        std::uint64_t min;
        std::uint64_t max;
    } checks[] = {
        {"max_file_bytes", limits.maxFileBytes, 1, C::maxFileBytes},
        {"read_chunk_bytes", limits.readChunkBytes, C::minReadChunkBytes, C::maxReadChunkBytes},
        {"max_sections", limits.maxSections, 1, C::maxSections},
        {"max_imported_modules", limits.maxImportedModules, 1, C::maxImportedModules},
        {"max_imported_functions", limits.maxImportedFunctions, 1, C::maxImportedFunctions},
        {"max_exports", limits.maxExports, 1, C::maxExports},
        {"max_resource_entries", limits.maxResourceEntries, 1, C::maxResourceEntries},
        {"max_strings", limits.maxStrings, 1, C::maxStrings},
        {"max_string_bytes", limits.maxStringBytes, 1, C::maxStringBytes},
        {"min_string_length", limits.minStringLength, 2, limits.maxStringLength},
        {"max_string_length", limits.maxStringLength, 2, C::maxStringLength},
    };

    for (const auto& check : checks) {
        if (Status status = checkRange(check.name, check.value, check.min, check.max); !status) {
            return status;
        }
    }
    return {};
}

} // namespace sectoryn
