#pragma once

#include "detectors/Finding.hpp"
#include "parsers/FieldStatus.hpp"

#include <QColor>
#include <QString>

#include <cstdint>
#include <string>
#include <string_view>

namespace sectoryn::ui {

// Text from analyzed files is untrusted. Every helper here returns plain text, and every widget
// that shows it must use Qt::PlainText so markup in a file is never interpreted.
[[nodiscard]] QString toQString(std::string_view text);

[[nodiscard]] QString hex(std::uint64_t value, int digits = 0);
[[nodiscard]] QString byteSize(std::uint64_t bytes);
// COFF timestamps are seconds since 1970 UTC. Zero and implausible values are shown as such.
[[nodiscard]] QString coffTimestamp(std::uint32_t seconds);
[[nodiscard]] QString fieldStatusText(const FieldStatus& status);

[[nodiscard]] QString severityText(Severity severity);
[[nodiscard]] QString confidenceText(Confidence confidence);
[[nodiscard]] QColor severityColor(Severity severity);

} // namespace sectoryn::ui
