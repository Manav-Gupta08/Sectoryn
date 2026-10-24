#include "analysis/IndicatorClassifier.hpp"
#include "analysis/StringExtractor.hpp"
#include "support/TempDir.hpp"
#include "utilities/FileReader.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

using namespace std::string_literals;

std::span<const std::byte> bytesOf(std::string_view text) {
    return std::as_bytes(std::span(text));
}

std::string utf16(std::string_view ascii) {
    std::string out;
    for (const char c : ascii) {
        out.push_back(c);
        out.push_back('\0');
    }
    return out;
}

StringExtraction extract(std::string_view data, AnalysisLimits limits = {}) {
    StringExtractor extractor(limits);
    extractor.feed(bytesOf(data));
    return extractor.finish();
}

std::vector<std::string> texts(const StringExtraction& extraction) {
    std::vector<std::string> out;
    for (const ExtractedString& s : extraction.strings) {
        out.push_back(s.text);
    }
    return out;
}

TEST(StringExtractor, FindsAsciiRuns) {
    const StringExtraction result = extract("\x01hello world\0\xFFshort\0kernel32.dll"s);
    EXPECT_EQ(texts(result), (std::vector<std::string>{"hello world", "short", "kernel32.dll"}));
    ASSERT_EQ(result.strings.size(), 3U);
    EXPECT_EQ(result.strings[0].offset, 1U);
    EXPECT_EQ(result.strings[0].encoding, StringEncoding::Ascii);
    EXPECT_FALSE(result.limitReached);
}

TEST(StringExtractor, RespectsMinimumLength) {
    EXPECT_TRUE(extract("abcd\0"s).strings.empty());
    EXPECT_EQ(extract("abcde\0"s).strings.size(), 1U);
}

TEST(StringExtractor, FindsUtf16AtEvenAndOddOffsets) {
    const std::string data = "\xFF"s + utf16("Odd offset") + "\xFF\xFF"s + utf16("Even!");
    const StringExtraction result = extract(data);
    ASSERT_EQ(result.strings.size(), 2U);
    EXPECT_EQ(result.strings[0].text, "Odd offset");
    EXPECT_EQ(result.strings[0].offset, 1U);
    EXPECT_EQ(result.strings[0].encoding, StringEncoding::Utf16Le);
    EXPECT_EQ(result.strings[1].text, "Even!");
    EXPECT_EQ(result.strings[1].offset, 23U);
}

TEST(StringExtractor, JoinsRunsAcrossChunks) {
    const std::string data = "prefix-" + utf16("WideString") + "\x01-tail-text"s;
    const StringExtraction whole = extract(data);

    for (const std::size_t chunk : {1U, 2U, 3U, 7U}) {
        StringExtractor extractor(AnalysisLimits{});
        for (std::size_t pos = 0; pos < data.size(); pos += chunk) {
            extractor.feed(bytesOf(std::string_view(data).substr(pos, chunk)));
        }
        EXPECT_EQ(extractor.finish().strings, whole.strings) << "chunk size " << chunk;
    }
}

TEST(StringExtractor, TruncatesLongStrings) {
    AnalysisLimits limits;
    limits.maxStringLength = 8;
    const StringExtraction result = extract(std::string(20, 'A') + "\0"s, limits);
    ASSERT_EQ(result.strings.size(), 1U);
    EXPECT_EQ(result.strings[0].text, "AAAAAAAA");
    EXPECT_TRUE(result.strings[0].truncated);
}

TEST(StringExtractor, StopsAtStringCountLimit) {
    AnalysisLimits limits;
    limits.maxStrings = 2;
    StringExtractor extractor(limits);
    const std::string data = "first\0second\0third\0fourth\0"s;
    EXPECT_FALSE(extractor.feed(bytesOf(data)));
    const StringExtraction result = extractor.finish();
    EXPECT_EQ(texts(result), (std::vector<std::string>{"first", "second"}));
    EXPECT_TRUE(result.limitReached);
}

TEST(StringExtractor, StopsAtByteLimit) {
    AnalysisLimits limits;
    limits.maxStringBytes = 12;
    const StringExtraction result = extract("abcdefgh\0ijklmnop\0"s, limits);
    EXPECT_EQ(texts(result), (std::vector<std::string>{"abcdefgh"}));
    EXPECT_TRUE(result.limitReached);
}

TEST(StringExtractor, ExtractsFromFile) {
    const test::TempDir dir;
    const std::string data = std::string(70000, '\0') + "C:\\Windows\\evil.exe\0"s;
    Result<FileReader> reader = FileReader::open(dir.write("strings.bin", data));
    ASSERT_TRUE(reader.hasValue());

    AnalysisLimits limits;
    limits.readChunkBytes = 4096;
    const Result<StringExtraction> result = extractStrings(reader.value(), limits, {});
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    ASSERT_EQ(result.value().strings.size(), 1U);
    EXPECT_EQ(result.value().strings[0].offset, 70000U);
}

TEST(StringExtractor, ExtractionIsCancellable) {
    const test::TempDir dir;
    Result<FileReader> reader = FileReader::open(dir.write("a.bin", std::string(8192, 'a')));
    ASSERT_TRUE(reader.hasValue());
    CancellationSource source;
    source.request_stop();
    const Result<StringExtraction> result = extractStrings(reader.value(), {}, source.get_token());
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::Cancelled);
}

std::vector<std::string> valuesOf(std::string_view text, IndicatorKind kind) {
    std::vector<std::string> values;
    for (const Indicator& indicator : classifyString(text)) {
        if (indicator.kind == kind) {
            values.push_back(indicator.value);
        }
    }
    return values;
}

TEST(IndicatorClassifier, FindsUrlsAndHosts) {
    const std::string text = "get HTTPS://user@Update.Example.com:8443/a?b=1 and http://10.1.2.3/x";
    EXPECT_EQ(valuesOf(text, IndicatorKind::Url),
              (std::vector<std::string>{"http://10.1.2.3/x",
                                        "HTTPS://user@Update.Example.com:8443/a?b=1"}));
    EXPECT_EQ(valuesOf(text, IndicatorKind::Domain),
              (std::vector<std::string>{"update.example.com"}));
    EXPECT_EQ(valuesOf(text, IndicatorKind::IpV4Address), (std::vector<std::string>{"10.1.2.3"}));
}

TEST(IndicatorClassifier, IgnoresSchemeWithoutHost) {
    EXPECT_TRUE(valuesOf("http:// nothing", IndicatorKind::Url).empty());
}

TEST(IndicatorClassifier, FindsStandaloneDomains) {
    EXPECT_EQ(valuesOf("beacon to c2.evil-site.ru now", IndicatorKind::Domain),
              (std::vector<std::string>{"c2.evil-site.ru"}));
    EXPECT_TRUE(valuesOf("System.Net.Http kernel32.dll", IndicatorKind::Domain).empty());
    EXPECT_TRUE(valuesOf("-bad-.com", IndicatorKind::Domain).empty());
}

TEST(IndicatorClassifier, ValidatesIpAddresses) {
    EXPECT_EQ(valuesOf("connect 192.168.0.1:80", IndicatorKind::IpV4Address),
              (std::vector<std::string>{"192.168.0.1"}));
    EXPECT_TRUE(valuesOf("256.1.1.1", IndicatorKind::IpV4Address).empty());
    EXPECT_TRUE(valuesOf("version 10.0.19041.1", IndicatorKind::IpV4Address).empty());
    EXPECT_TRUE(valuesOf("1.2.3", IndicatorKind::IpV4Address).empty());
}

TEST(IndicatorClassifier, FindsPaths) {
    EXPECT_EQ(valuesOf("copy C:\\Users\\Public\\a.exe now", IndicatorKind::FilePath),
              (std::vector<std::string>{"C:\\Users\\Public\\a.exe"}));
    EXPECT_EQ(valuesOf("%APPDATA%\\svc\\host.exe", IndicatorKind::FilePath),
              (std::vector<std::string>{"%APPDATA%\\svc\\host.exe"}));
    EXPECT_EQ(valuesOf("\\\\.\\PhysicalDrive0", IndicatorKind::FilePath),
              (std::vector<std::string>{"\\\\.\\PhysicalDrive0"}));
    EXPECT_EQ(valuesOf("\\\\fileserver\\share\\x", IndicatorKind::UncPath),
              (std::vector<std::string>{"\\\\fileserver\\share\\x"}));
    EXPECT_TRUE(valuesOf("ratio 3:\\ not a drive", IndicatorKind::FilePath).empty());
}

TEST(IndicatorClassifier, FindsRegistryKeys) {
    EXPECT_EQ(valuesOf("HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion  ",
                       IndicatorKind::RegistryKey),
              (std::vector<std::string>{"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion"}));
    const std::string runKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    EXPECT_EQ(valuesOf(runKey, IndicatorKind::RegistryKey).size(), 1U);
    EXPECT_TRUE(valuesOf("SHKU\\x", IndicatorKind::RegistryKey).empty());
}

TEST(IndicatorClassifier, FindsCommandsAndPersistence) {
    const std::string text =
        "powershell -ExecutionPolicy Bypass -EncodedCommand AAAA & cmd.exe /c schtasks /create";
    EXPECT_EQ(valuesOf(text, IndicatorKind::PowerShell),
              (std::vector<std::string>{"powershell", "-EncodedCommand",
                                        "-ExecutionPolicy Bypass"}));
    EXPECT_EQ(valuesOf(text, IndicatorKind::CommandLine), (std::vector<std::string>{"cmd.exe /c"}));
    EXPECT_EQ(valuesOf(text, IndicatorKind::Persistence),
              (std::vector<std::string>{"schtasks /create"}));
    EXPECT_EQ(valuesOf("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                       IndicatorKind::Persistence),
              (std::vector<std::string>{"CurrentVersion\\Run"}));
}

TEST(IndicatorClassifier, FindsEncodedData) {
    const std::string encoded = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYmFzZTY0IGRhdGEu";
    EXPECT_EQ(valuesOf("payload=" + encoded, IndicatorKind::EncodedData),
              (std::vector<std::string>{encoded}));
    // Long identifiers without mixed case and digits are not reported.
    EXPECT_TRUE(valuesOf(std::string(48, 'a'), IndicatorKind::EncodedData).empty());
}

TEST(IndicatorClassifier, PlainTextHasNoIndicators) {
    EXPECT_TRUE(classifyString("This program cannot be run in DOS mode.").empty());
}

TEST(IndicatorClassifier, BoundsIndicatorsPerString) {
    std::string text;
    for (int i = 0; i < 100; ++i) {
        text += "10.0.0." + std::to_string(i) + " ";
    }
    EXPECT_LE(classifyString(text).size(), 32U);
}

TEST(IndicatorClassifier, MapsOffsetsToFile) {
    const std::string data = "\0\0"s + utf16("see http://a.example.com");
    const StringExtraction extraction = extract(data);
    const std::vector<Indicator> indicators = classifyStrings(extraction);
    const auto url = std::ranges::find(indicators, IndicatorKind::Url, &Indicator::kind);
    ASSERT_NE(url, indicators.end());
    EXPECT_EQ(url->stringIndex, 0U);
    EXPECT_EQ(url->offset, 2U + 4U * 2U);
}

} // namespace
} // namespace sectoryn
