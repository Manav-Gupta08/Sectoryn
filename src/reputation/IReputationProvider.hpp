#pragma once

#include "core/Result.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sectoryn {

struct HttpRequest {
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
};

struct HttpResponse {
    // 0 when no response was received, e.g. after a network error or timeout.
    int status = 0;
    std::string body;
    std::optional<std::chrono::seconds> retryAfter;
};

// What a reputation service says about a hash. This is external information: it is shown next
// to the local analysis and never changes its findings or score.
struct ReputationReport {
    std::string provider;
    std::string sha256;
    // False when the service has no record of the hash.
    bool known = false;
    std::uint32_t malicious = 0;
    std::uint32_t suspicious = 0;
    std::uint32_t harmless = 0;
    std::uint32_t undetected = 0;
    // When the service last analyzed the file, in seconds since 1970 UTC.
    std::optional<std::int64_t> lastAnalysis;
    std::string permalink;
    std::chrono::system_clock::time_point retrievedAt;
};

// A hash reputation service. Providers only build requests and parse responses; the caller
// performs the transfer, so the network code stays in one place and providers stay testable.
class IReputationProvider {
public:
    virtual ~IReputationProvider() = default;

    [[nodiscard]] virtual std::string_view id() const noexcept = 0;
    [[nodiscard]] virtual std::string_view displayName() const noexcept = 0;
    // Plain-language statement of what is sent and to whom, shown before the user agrees.
    [[nodiscard]] virtual std::string disclosure() const = 0;

    [[nodiscard]] virtual Result<HttpRequest> buildRequest(std::string_view sha256) const = 0;
    [[nodiscard]] virtual Result<ReputationReport>
    parseResponse(std::string_view sha256, const HttpResponse& response) const = 0;

protected:
    IReputationProvider() = default;
    IReputationProvider(const IReputationProvider&) = default;
    IReputationProvider& operator=(const IReputationProvider&) = default;
    IReputationProvider(IReputationProvider&&) = default;
    IReputationProvider& operator=(IReputationProvider&&) = default;
};

// 64 hexadecimal digits.
[[nodiscard]] bool isSha256Hex(std::string_view text) noexcept;

} // namespace sectoryn
