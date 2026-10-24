#pragma once

#include "parsers/PeModel.hpp"

namespace sectoryn {

// Checks header fields against each other and against the file size, appending one
// StructuralIssue per problem. Expects sections, data directories and the certificate table
// to have been extracted already. Issues describe inconsistencies; they are not verdicts.
void validateHeaders(PeImage& image);

} // namespace sectoryn
