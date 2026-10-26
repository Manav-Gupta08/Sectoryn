#include "reports/HtmlEscape.hpp"

#include <gtest/gtest.h>

#include <string>

namespace sectoryn {
namespace {

using namespace std::string_literals;

const std::string kReplacement = "\xEF\xBF\xBD";

TEST(HtmlEscape, LeavesPlainTextAlone) {
    EXPECT_EQ(escapeHtml("KERNEL32.dll!VirtualAllocEx"), "KERNEL32.dll!VirtualAllocEx");
    EXPECT_EQ(escapeHtml(""), "");
}

TEST(HtmlEscape, EscapesMarkupCharacters) {
    EXPECT_EQ(escapeHtml(R"(<a href="x" title='y'>&</a>)"),
              "&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;&amp;&lt;/a&gt;");
}

TEST(HtmlEscape, NeutralizesScriptInjection) {
    const std::string escaped = escapeHtml("</style><script>alert(1)</script>");
    EXPECT_EQ(escaped.find('<'), std::string::npos);
    EXPECT_EQ(escaped.find('>'), std::string::npos);
    EXPECT_EQ(escaped, "&lt;/style&gt;&lt;script&gt;alert(1)&lt;/script&gt;");
}

TEST(HtmlEscape, CannotBreakOutOfQuotedAttributes) {
    const std::string escaped = escapeHtml(R"(x" onmouseover="alert(1))");
    EXPECT_EQ(escaped.find('"'), std::string::npos);
    EXPECT_EQ(escapeHtml("x' autofocus onfocus='alert(1)").find('\''), std::string::npos);
}

TEST(HtmlEscape, DoesNotDecodeExistingEntities) {
    EXPECT_EQ(escapeHtml("&lt;script&gt;"), "&amp;lt;script&amp;gt;");
}

TEST(HtmlEscape, KeepsWellFormedUtf8) {
    const std::string text = "caf\xC3\xA9 \xE4\xB8\xAD\xE6\x96\x87 \xF0\x9F\x94\x92";
    EXPECT_EQ(escapeHtml(text), text);
}

TEST(HtmlEscape, KeepsTabsAndLineBreaks) {
    EXPECT_EQ(escapeHtml("a\tb\r\nc"), "a\tb\r\nc");
}

TEST(HtmlEscape, ReplacesControlCharacters) {
    EXPECT_EQ(escapeHtml("a\0b"s), "a" + kReplacement + "b");
    EXPECT_EQ(escapeHtml("a\x1B[31m"), "a" + kReplacement + "[31m");
    EXPECT_EQ(escapeHtml("\x7F"), kReplacement);
    // U+0085, NEXT LINE, is a C1 control.
    EXPECT_EQ(escapeHtml("a\xC2\x85z"), "a" + kReplacement + "z");
    // U+00A0 is the first character after the C1 block and is kept.
    EXPECT_EQ(escapeHtml("\xC2\xA0"), "\xC2\xA0");
}

TEST(HtmlEscape, ReplacesStrayBytes) {
    EXPECT_EQ(escapeHtml("a\x80z"), "a" + kReplacement + "z");
    EXPECT_EQ(escapeHtml("\xFF\xFE"), kReplacement + kReplacement);
    EXPECT_EQ(escapeHtml("\xF5\x80\x80\x80"), kReplacement + kReplacement + kReplacement +
                                                  kReplacement);
}

TEST(HtmlEscape, RejectsOverlongEncodings) {
    // '/' and '<' encoded in two bytes would slip past a check for the ASCII characters.
    EXPECT_EQ(escapeHtml("\xC0\xAF"), kReplacement + kReplacement);
    EXPECT_EQ(escapeHtml("\xC0\xBC"), kReplacement + kReplacement);
    EXPECT_EQ(escapeHtml("\xE0\x80\xBC"), kReplacement + kReplacement + kReplacement);
    EXPECT_EQ(escapeHtml("\xF0\x80\x80\xBC"),
              kReplacement + kReplacement + kReplacement + kReplacement);
}

TEST(HtmlEscape, RejectsSurrogatesAndOutOfRangeCodePoints) {
    // U+D800 encoded directly.
    EXPECT_EQ(escapeHtml("\xED\xA0\x80"), kReplacement + kReplacement + kReplacement);
    // U+110000.
    EXPECT_EQ(escapeHtml("\xF4\x90\x80\x80"),
              kReplacement + kReplacement + kReplacement + kReplacement);
    // U+10FFFF is the last valid code point.
    EXPECT_EQ(escapeHtml("\xF4\x8F\xBF\xBF"), "\xF4\x8F\xBF\xBF");
}

TEST(HtmlEscape, ReplacesTruncatedSequenceOnce) {
    EXPECT_EQ(escapeHtml("ab\xE4\xB8"), "ab" + kReplacement);
    // The interrupted sequence is replaced, and the ASCII byte that interrupted it survives.
    EXPECT_EQ(escapeHtml("\xE4\xB8<"), kReplacement + "&lt;");
}

TEST(HtmlEscape, AppendKeepsExistingContent) {
    std::string out = "<p>";
    appendHtmlEscaped(out, "1 < 2");
    out += "</p>";
    EXPECT_EQ(out, "<p>1 &lt; 2</p>");
}

} // namespace
} // namespace sectoryn
