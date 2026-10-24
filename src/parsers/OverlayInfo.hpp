#pragma once

#include "parsers/PeModel.hpp"

namespace sectoryn {

// Both functions derive their results from values already in the image (file size, section
// table and data directories); they read no file data. Call describeCertificateTable first.
void describeCertificateTable(PeImage& image);
void describeOverlay(PeImage& image);

} // namespace sectoryn
