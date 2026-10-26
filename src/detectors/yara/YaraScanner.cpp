#include "detectors/yara/YaraScanner.hpp"

#include "detectors/yara/YaraApi.hpp"

#include <format>
#include <utility>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

namespace sectoryn {

namespace {

struct ScannerDeleter {
    void operator()(YR_SCANNER* scanner) const noexcept { yr_scanner_destroy(scanner); }
};

// Owns a read-only handle to the scanned file.
class ReadOnlyFile {
public:
    explicit ReadOnlyFile(const std::filesystem::path& path) {
#ifdef _WIN32
        handle_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
#else
        handle_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
#endif
    }

    ~ReadOnlyFile() {
        if (isOpen()) {
#ifdef _WIN32
            CloseHandle(handle_);
#else
            ::close(handle_);
#endif
        }
    }

    ReadOnlyFile(const ReadOnlyFile&) = delete;
    ReadOnlyFile& operator=(const ReadOnlyFile&) = delete;
    ReadOnlyFile(ReadOnlyFile&&) = delete;
    ReadOnlyFile& operator=(ReadOnlyFile&&) = delete;

    [[nodiscard]] bool isOpen() const noexcept {
#ifdef _WIN32
        return handle_ != INVALID_HANDLE_VALUE;
#else
        return handle_ >= 0;
#endif
    }

    [[nodiscard]] YR_FILE_DESCRIPTOR handle() const noexcept { return handle_; }

private:
    YR_FILE_DESCRIPTOR handle_;
};

struct ScanState {
    const CancellationToken* token = nullptr;
    YaraScanResult* result = nullptr;
    bool failed = false;
};

std::string metadataValue(const YR_META* meta) {
    switch (meta->type) {
    case META_TYPE_INTEGER:
        return std::to_string(meta->integer);
    case META_TYPE_BOOLEAN:
        return meta->integer != 0 ? "true" : "false";
    default:
        return meta->string != nullptr ? meta->string : "";
    }
}

YaraMatch describeMatch(YR_SCAN_CONTEXT* context, const YR_RULE* rule) {
    YaraMatch match;
    match.rule = rule->identifier;
    match.ruleNamespace = rule->ns != nullptr ? rule->ns->name : "";

    const char* tag = nullptr;
    yr_rule_tags_foreach(rule, tag) {
        match.tags.emplace_back(tag);
    }
    const YR_META* meta = nullptr;
    yr_rule_metas_foreach(rule, meta) {
        match.metadata.push_back({.name = meta->identifier, .value = metadataValue(meta)});
    }
    const YR_STRING* string = nullptr;
    yr_rule_strings_foreach(rule, string) {
        const YR_MATCH* hit = nullptr;
        yr_string_matches_foreach(context, string, hit) {
            if (match.strings.size() >= YaraScanResult::kMaxStringMatches) {
                match.stringsTruncated = true;
                break;
            }
            match.strings.push_back({.identifier = string->identifier,
                                     .offset = static_cast<std::uint64_t>(hit->base + hit->offset),
                                     .length = static_cast<std::uint32_t>(hit->match_length)});
        }
    }
    return match;
}

// Called from C code, so no exception may escape.
int onScanMessage(YR_SCAN_CONTEXT* context, int message, void* messageData,
                  void* userData) noexcept {
    auto& state = *static_cast<ScanState*>(userData);
    if (state.token->stop_requested()) {
        return CALLBACK_ABORT;
    }
    try {
        if (message == CALLBACK_MSG_RULE_MATCHING) {
            if (state.result->matches.size() >= YaraScanResult::kMaxMatchingRules) {
                state.result->matchesTruncated = true;
                return CALLBACK_ABORT;
            }
            state.result->matches.push_back(
                describeMatch(context, static_cast<const YR_RULE*>(messageData)));
        } else if (message == CALLBACK_MSG_TOO_MANY_MATCHES) {
            state.result->tooManyMatches = true;
        }
    } catch (...) {
        state.failed = true;
        return CALLBACK_ERROR;
    }
    return CALLBACK_CONTINUE;
}

Error scanError(int status) {
    switch (status) {
    case ERROR_INSUFFICIENT_MEMORY:
        return Error{ErrorCode::ResourceLimitExceeded, "not enough memory for the YARA scan"};
    case ERROR_COULD_NOT_MAP_FILE:
    case ERROR_COULD_NOT_OPEN_FILE:
        return Error{ErrorCode::IoFailure, "YARA could not read the file"};
    default:
        return Error{ErrorCode::ExternalServiceFailure,
                     std::format("the YARA scan failed (libyara error {})", status)};
    }
}

} // namespace

Result<YaraScanResult> scanFileWithYara(const YaraRuleSet& rules,
                                        const std::filesystem::path& path,
                                        const CancellationToken& token,
                                        const YaraScanOptions& options) {
    if (Status status = checkCancelled(token); !status) {
        return std::move(status).error();
    }
    const ReadOnlyFile file(path);
    if (!file.isOpen()) {
        return Error{ErrorCode::IoFailure, "cannot open the file for YARA scanning"};
    }

    YR_SCANNER* rawScanner = nullptr;
    if (yr_scanner_create(rules.native(), &rawScanner) != ERROR_SUCCESS) {
        return Error{ErrorCode::ResourceLimitExceeded, "cannot create a YARA scanner"};
    }
    const std::unique_ptr<YR_SCANNER, ScannerDeleter> scanner(rawScanner);

    YaraScanResult result;
    ScanState state{.token = &token, .result = &result};
    yr_scanner_set_callback(scanner.get(), onScanMessage, &state);
    yr_scanner_set_flags(scanner.get(), SCAN_FLAGS_REPORT_RULES_MATCHING);
    yr_scanner_set_timeout(scanner.get(), static_cast<int>(options.timeout.count()));

    const int status = yr_scanner_scan_fd(scanner.get(), file.handle());
    if (Status cancelled = checkCancelled(token); !cancelled) {
        return std::move(cancelled).error();
    }
    if (state.failed) {
        return Error{ErrorCode::ResourceLimitExceeded, "not enough memory for YARA matches"};
    }
    if (status == ERROR_SCAN_TIMEOUT) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("the YARA scan took longer than {} seconds",
                                 options.timeout.count())};
    }
    // Aborting because the match limit was reached is not a failure.
    if (status != ERROR_SUCCESS && !result.matchesTruncated) {
        return scanError(status);
    }
    return result;
}

} // namespace sectoryn
