#include "analysis/IndicatorClassifier.hpp"

#include <algorithm>
#include <array>
#include <iterator>
#include <string>
#include <utility>

namespace sectoryn {

namespace {

// Strings are capped at maxStringLength, but one string could still match many patterns.
constexpr std::size_t kMaxIndicatorsPerString = 32;
constexpr std::size_t kMinEncodedLength = 40;
constexpr std::size_t kMaxDomainLength = 253;
constexpr std::size_t kMaxLabelLength = 63;

constexpr std::array<std::string_view, 4> kUrlSchemes = {"http://", "https://", "ftp://",
                                                         "ftps://"};

// Matched only when written in lowercase, which keeps names such as "System.Net" out.
constexpr std::array<std::string_view, 18> kDomainSuffixes = {
    "com", "net", "org", "info", "biz", "io", "xyz", "top", "ru",
    "cn", "su", "onion", "tk", "pw", "cc", "club", "online", "site",
};

constexpr std::array<std::string_view, 11> kRegistryHives = {
    "hkey_local_machine\\",
    "hkey_current_user\\",
    "hkey_classes_root\\",
    "hkey_users\\",
    "hkey_current_config\\",
    "hklm\\",
    "hkcu\\",
    "hkcr\\",
    "hku\\",
    "\\registry\\machine\\",
    "\\registry\\user\\",
};
constexpr std::string_view kHivelessRunKey = "software\\microsoft\\windows\\currentversion\\";

constexpr std::array<std::string_view, 15> kPowerShellTerms = {
    "powershell",
    "pwsh",
    "-encodedcommand",
    "invoke-expression",
    "iex(",
    "iex (",
    "downloadstring",
    "downloadfile",
    "frombase64string",
    "-executionpolicy bypass",
    "-exec bypass",
    "invoke-webrequest",
    "net.webclient",
    "start-bitstransfer",
    "-windowstyle hidden",
};

constexpr std::array<std::string_view, 18> kCommandTerms = {
    "cmd.exe /c",
    "cmd /c",
    "cmd.exe /k",
    "rundll32",
    "regsvr32",
    "mshta",
    "certutil -urlcache",
    "certutil.exe -urlcache",
    "certutil -decode",
    "bitsadmin /transfer",
    "wmic process call create",
    "vssadmin delete shadows",
    "vssadmin.exe delete shadows",
    "bcdedit /set",
    "wevtutil cl",
    "netsh advfirewall",
    "reg add",
    "reg delete",
};

constexpr std::array<std::string_view, 10> kPersistenceTerms = {
    "currentversion\\run",
    "currentversion\\policies\\explorer\\run",
    "winlogon\\shell",
    "winlogon\\userinit",
    "image file execution options",
    "appinit_dlls",
    "start menu\\programs\\startup",
    "schtasks /create",
    "schtasks.exe /create",
    "currentcontrolset\\services\\",
};

bool isDigit(char c) {
    return c >= '0' && c <= '9';
}

bool isLower(char c) {
    return c >= 'a' && c <= 'z';
}

bool isUpper(char c) {
    return c >= 'A' && c <= 'Z';
}

bool isAlpha(char c) {
    return isLower(c) || isUpper(c);
}

bool isAlnum(char c) {
    return isDigit(c) || isAlpha(c);
}

char toLower(char c) {
    return isUpper(c) ? static_cast<char>(c - 'A' + 'a') : c;
}

bool isSpace(char c) {
    return c == ' ' || c == '\t';
}

bool isUrlChar(char c) {
    return !isSpace(c) && c != '"' && c != '\'' && c != '<' && c != '>' && c != '`';
}

bool isPathChar(char c) {
    return !isSpace(c) && c != '"' && c != '\'' && c != '<' && c != '>' && c != '|' &&
           c != '*' && c != '?';
}

bool isBase64Char(char c) {
    return isAlnum(c) || c == '+' || c == '/';
}

struct TextSpan {
    std::size_t start;
    std::size_t length;

    // Positions before start wrap around to large values and fail the comparison.
    [[nodiscard]] bool contains(std::size_t pos) const { return pos - start < length; }
};

class Matcher {
public:
    explicit Matcher(std::string_view text)
        : text_(text) {
        lower_.reserve(text.size());
        std::ranges::transform(text, std::back_inserter(lower_), toLower);
    }

    void run() {
        findUrls();
        findDomains();
        findIpAddresses();
        findPaths();
        findRegistryKeys();
        findTerms(kPowerShellTerms, IndicatorKind::PowerShell);
        findTerms(kCommandTerms, IndicatorKind::CommandLine);
        findTerms(kPersistenceTerms, IndicatorKind::Persistence);
        findEncodedData();
    }

    std::vector<Indicator> take() { return std::move(found_); }

private:
    void add(IndicatorKind kind, std::size_t position, std::string_view value) {
        if (found_.size() >= kMaxIndicatorsPerString) {
            return;
        }
        const bool duplicate = std::ranges::any_of(found_, [&](const Indicator& existing) {
            return existing.kind == kind && existing.value == value;
        });
        if (!duplicate) {
            found_.push_back({kind, std::string(value), 0, position});
        }
    }

    std::size_t extent(std::size_t from, bool (*accept)(char)) const {
        std::size_t end = from;
        while (end < text_.size() && accept(text_[end])) {
            ++end;
        }
        return end;
    }

    static bool isIpV4(std::string_view text, std::size_t& length) {
        std::size_t pos = 0;
        for (int octet = 0; octet < 4; ++octet) {
            if (octet > 0) {
                if (pos >= text.size() || text[pos] != '.') {
                    return false;
                }
                ++pos;
            }
            const std::size_t start = pos;
            unsigned value = 0;
            while (pos < text.size() && isDigit(text[pos]) && pos - start < 3) {
                value = value * 10 + static_cast<unsigned>(text[pos] - '0');
                ++pos;
            }
            if (pos == start || value > 255) {
                return false;
            }
        }
        // A fifth number or digit means this is a version string, not an address.
        if (pos < text.size() && (isDigit(text[pos]) || text[pos] == '.')) {
            return false;
        }
        length = pos;
        return true;
    }

    static bool isDomain(std::string_view token) {
        if (token.size() > kMaxDomainLength || token.find('.') == std::string_view::npos) {
            return false;
        }
        std::size_t start = 0;
        while (true) {
            const std::size_t dot = token.find('.', start);
            const std::string_view label = token.substr(start, dot - start);
            if (label.empty() || label.size() > kMaxLabelLength || label.front() == '-' ||
                label.back() == '-') {
                return false;
            }
            if (dot == std::string_view::npos) {
                return std::ranges::find(kDomainSuffixes, label) != kDomainSuffixes.end();
            }
            start = dot + 1;
        }
    }

    void addHost(std::size_t position, std::string_view host) {
        std::size_t length = 0;
        if (isIpV4(host, length) && length == host.size()) {
            add(IndicatorKind::IpV4Address, position, host);
            return;
        }
        std::string lowered(host);
        std::ranges::transform(lowered, lowered.begin(), toLower);
        if (lowered.find('.') != std::string::npos) {
            add(IndicatorKind::Domain, position, lowered);
        }
    }

    void findUrls() {
        for (const std::string_view scheme : kUrlSchemes) {
            for (std::size_t pos = lower_.find(scheme); pos != std::string::npos;
                 pos = lower_.find(scheme, pos + 1)) {
                const std::size_t hostStart = pos + scheme.size();
                const std::size_t end = extent(hostStart, isUrlChar);
                if (end == hostStart || !isAlnum(text_[hostStart])) {
                    continue;
                }
                add(IndicatorKind::Url, pos, text_.substr(pos, end - pos));
                urlSpans_.push_back({pos, end - pos});

                std::string_view authority = text_.substr(hostStart, end - hostStart);
                authority = authority.substr(0, authority.find_first_of("/?#"));
                if (const std::size_t at = authority.rfind('@'); at != std::string_view::npos) {
                    authority.remove_prefix(at + 1);
                }
                addHost(hostStart, authority.substr(0, authority.find(':')));
            }
        }
    }

    void findDomains() {
        const auto isDomainChar = [](char c) { return isAlnum(c) || c == '.' || c == '-'; };
        std::size_t pos = 0;
        while (pos < text_.size()) {
            if (!isDomainChar(text_[pos])) {
                ++pos;
                continue;
            }
            std::size_t end = pos;
            while (end < text_.size() && isDomainChar(text_[end])) {
                ++end;
            }
            // Hosts inside URLs were already reported by findUrls.
            const bool insideUrl = std::ranges::any_of(
                urlSpans_, [pos](const TextSpan& span) { return span.contains(pos); });
            const std::string_view token = text_.substr(pos, end - pos);
            if (!insideUrl && isDomain(token)) {
                addHost(pos, token);
            }
            pos = end;
        }
    }

    void findIpAddresses() {
        for (std::size_t pos = 0; pos < text_.size(); ++pos) {
            const bool boundary = pos == 0 || (!isDigit(text_[pos - 1]) && text_[pos - 1] != '.');
            std::size_t length = 0;
            if (boundary && isDigit(text_[pos]) && isIpV4(text_.substr(pos), length)) {
                add(IndicatorKind::IpV4Address, pos, text_.substr(pos, length));
                pos += length;
            }
        }
    }

    void findPaths() {
        for (std::size_t pos = 0; pos + 2 < text_.size(); ++pos) {
            const bool driveStart = pos == 0 || !isAlnum(text_[pos - 1]);
            if (driveStart && isAlpha(text_[pos]) && text_[pos + 1] == ':' &&
                text_[pos + 2] == '\\') {
                const std::size_t end = extent(pos, isPathChar);
                add(IndicatorKind::FilePath, pos, text_.substr(pos, end - pos));
                pos = end;
            } else if (text_[pos] == '%') {
                const std::size_t close = text_.find('%', pos + 1);
                const bool envPath = close != std::string_view::npos && close > pos + 1 &&
                                     close + 1 < text_.size() && text_[close + 1] == '\\';
                if (envPath) {
                    const std::size_t end = extent(pos, isPathChar);
                    add(IndicatorKind::FilePath, pos, text_.substr(pos, end - pos));
                    pos = end;
                }
            } else if (text_[pos] == '\\' && text_[pos + 1] == '\\') {
                const char next = text_[pos + 2];
                const bool device = next == '.' || next == '?';
                if (device || isAlnum(next)) {
                    const std::size_t end = extent(pos, isPathChar);
                    add(device ? IndicatorKind::FilePath : IndicatorKind::UncPath, pos,
                        text_.substr(pos, end - pos));
                    pos = end;
                }
            }
        }
    }

    void findRegistryKeys() {
        bool foundHive = false;
        for (const std::string_view hive : kRegistryHives) {
            for (std::size_t pos = lower_.find(hive); pos != std::string::npos;
                 pos = lower_.find(hive, pos + 1)) {
                // Require a boundary so that "hku\" is not found inside a longer word.
                if (pos > 0 && isAlnum(text_[pos - 1])) {
                    continue;
                }
                addRegistryKey(pos);
                foundHive = true;
            }
        }
        if (!foundHive) {
            if (const std::size_t pos = lower_.find(kHivelessRunKey); pos != std::string::npos) {
                addRegistryKey(pos);
            }
        }
    }

    void addRegistryKey(std::size_t pos) {
        // Key names may contain spaces, so the key runs to the next quote or the end.
        std::size_t end = text_.find_first_of("\"'", pos);
        end = end == std::string_view::npos ? text_.size() : end;
        while (end > pos && isSpace(text_[end - 1])) {
            --end;
        }
        add(IndicatorKind::RegistryKey, pos, text_.substr(pos, end - pos));
    }

    template <std::size_t N>
    void findTerms(const std::array<std::string_view, N>& terms, IndicatorKind kind) {
        for (const std::string_view term : terms) {
            if (const std::size_t pos = lower_.find(term); pos != std::string::npos) {
                add(kind, pos, text_.substr(pos, term.size()));
            }
        }
    }

    void findEncodedData() {
        std::size_t pos = 0;
        while (pos < text_.size()) {
            if (!isBase64Char(text_[pos])) {
                ++pos;
                continue;
            }
            std::size_t end = extent(pos, isBase64Char);
            std::size_t padded = end;
            while (padded < text_.size() && padded - end < 2 && text_[padded] == '=') {
                ++padded;
            }
            const std::string_view run = text_.substr(pos, padded - pos);
            const bool mixed = std::ranges::any_of(run, isDigit) &&
                               std::ranges::any_of(run, isLower) &&
                               std::ranges::any_of(run, isUpper);
            if (run.size() >= kMinEncodedLength && run.size() % 4 == 0 && mixed) {
                add(IndicatorKind::EncodedData, pos, run);
            }
            pos = padded;
        }
    }

    std::string_view text_;
    std::string lower_;
    std::vector<TextSpan> urlSpans_;
    std::vector<Indicator> found_;
};

} // namespace

std::string_view toString(IndicatorKind kind) noexcept {
    switch (kind) {
    case IndicatorKind::Url:
        return "URL";
    case IndicatorKind::Domain:
        return "domain";
    case IndicatorKind::IpV4Address:
        return "IPv4 address";
    case IndicatorKind::FilePath:
        return "file path";
    case IndicatorKind::UncPath:
        return "UNC path";
    case IndicatorKind::RegistryKey:
        return "registry key";
    case IndicatorKind::PowerShell:
        return "PowerShell";
    case IndicatorKind::CommandLine:
        return "command line";
    case IndicatorKind::Persistence:
        return "persistence reference";
    case IndicatorKind::EncodedData:
        return "encoded data";
    }
    return "unknown";
}

std::vector<Indicator> classifyString(std::string_view text) {
    Matcher matcher(text);
    matcher.run();
    return matcher.take();
}

std::vector<Indicator> classifyStrings(const StringExtraction& extraction) {
    std::vector<Indicator> indicators;
    for (std::size_t i = 0; i < extraction.strings.size(); ++i) {
        const ExtractedString& string = extraction.strings[i];
        const std::uint64_t unitSize = string.encoding == StringEncoding::Utf16Le ? 2 : 1;
        for (Indicator& indicator : classifyString(string.text)) {
            indicator.stringIndex = i;
            indicator.offset = string.offset + indicator.offset * unitSize;
            indicators.push_back(std::move(indicator));
        }
    }
    return indicators;
}

} // namespace sectoryn
