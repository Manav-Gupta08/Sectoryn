#pragma once

#include <string>
#include <string_view>

namespace sectoryn {

// Appends `text` escaped for HTML element content and quoted attribute values. Invalid UTF-8
// and control characters other than tab, line feed and carriage return become U+FFFD, so text
// taken from an analyzed file can neither inject markup nor make the document malformed.
void appendHtmlEscaped(std::string& out, std::string_view text);

[[nodiscard]] std::string escapeHtml(std::string_view text);

} // namespace sectoryn
