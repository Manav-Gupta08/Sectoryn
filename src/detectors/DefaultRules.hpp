#pragma once

#include "core/Result.hpp"
#include "detectors/ApiCatalogue.hpp"
#include "detectors/RuleRegistry.hpp"

namespace sectoryn {

// Every rule Sectoryn ships with, in a fixed order so results are reproducible.
[[nodiscard]] Result<RuleRegistry> createDefaultRules(ApiCatalogue catalogue);

} // namespace sectoryn
