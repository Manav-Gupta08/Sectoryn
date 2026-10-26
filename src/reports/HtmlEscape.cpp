#include "reports/HtmlEscape.hpp"

#include <cstddef>

namespace sectoryn {

namespace {

constexpr std::string_view kReplacement = "\xEF\xBF\xBD";

struct Sequence {
    std::size_t length = 1;
    bool valid = false;
};

// Checks the multi-byte UTF-8 sequence at the start of `text` against the well-formed byte
// ranges of the Unicode standard (no overlong forms, surrogates or values past U+10FFFF). An
// ill-formed sequence covers its longest valid prefix, which is then replaced as one unit.
Sequence readSequence(std::string_view text) {
    const auto lead = static_cast<unsigned char>(text.front());
    std::size_t expected = 0;
    unsigned char low = 0x80;
    unsigned char high = 0xBF;
    if (lead >= 0xC2 && lead <= 0xDF) {
        expected = 2;
    } else if (lead >= 0xE0 && lead <= 0xEF) {
        expected = 3;
        if (lead == 0xE0) {
            low = 0xA0;
        } else if (lead == 0xED) {
            high = 0x9F;
        }
    } else if (lead >= 0xF0 && lead <= 0xF4) {
        expected = 4;
        if (lead == 0xF0) {
            low = 0x90;
        } else if (lead == 0xF4) {
            high = 0x8F;
        }
    } else {
        return {};
    }

    Sequence sequence;
    while (sequence.length < expected && sequence.length < text.size()) {
        const auto next = static_cast<unsigned char>(text[sequence.length]);
        if (next < low || next > high) {
            return sequence;
        }
        low = 0x80;
        high = 0xBF;
        ++sequence.length;
    }
    sequence.valid = sequence.length == expected;
    return sequence;
}

// U+0080 to U+009F, the C1 control characters.
bool isC1Control(std::string_view sequence) {
    return sequence.size() == 2 && static_cast<unsigned char>(sequence[0]) == 0xC2 &&
           static_cast<unsigned char>(sequence[1]) < 0xA0;
}

} // namespace

void appendHtmlEscaped(std::string& out, std::string_view text) {
    out.reserve(out.size() + text.size());
    std::size_t i = 0;
    while (i < text.size()) {
        const auto c = static_cast<unsigned char>(text[i]);
        if (c >= 0x80) {
            const Sequence sequence = readSequence(text.substr(i));
            const std::string_view bytes = text.substr(i, sequence.length);
            out += sequence.valid && !isC1Control(bytes) ? bytes : kReplacement;
            i += sequence.length;
            continue;
        }
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&#39;";
            break;
        case '\t':
        case '\n':
        case '\r':
            out += static_cast<char>(c);
            break;
        default:
            if (c < 0x20 || c == 0x7F) {
                out += kReplacement;
            } else {
                out += static_cast<char>(c);
            }
            break;
        }
        ++i;
    }
}

std::string escapeHtml(std::string_view text) {
    std::string out;
    appendHtmlEscaped(out, text);
    return out;
}

} // namespace sectoryn
