#pragma once

#include "core/Limits.hpp"
#include "parsers/PeModel.hpp"

namespace LIEF::PE {
class Binary;
}

// Conversion from LIEF's object model to PeImage, split by structure. Each function fills its
// part of the image and records a FieldStatus; none of them throws on malformed input.
// Functions that depend on data directories expect extractDataDirectories to have run first.

namespace sectoryn::lief_detail {

void extractOptionalHeader(const LIEF::PE::Binary& binary, PeImage& image);
void extractDataDirectories(const LIEF::PE::Binary& binary, PeImage& image);
void extractSections(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                     PeImage& image);
void extractImports(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                    PeImage& image);
void extractExports(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                    PeImage& image);
void extractResources(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                      PeImage& image);
void extractDebug(const LIEF::PE::Binary& binary, PeImage& image);
void extractTls(const LIEF::PE::Binary& binary, PeImage& image);

} // namespace sectoryn::lief_detail
