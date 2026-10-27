#pragma once

#include "reputation/IReputationProvider.hpp"

#include <cstddef>
#include <string>
#include <string_view>

namespace sectoryn {

// Looks up a SHA-256 in the VirusTotal v3 API. Only the hash and the user's API key are sent;
// the file itself is never uploaded.
class VirusTotalProvider final : public IReputationProvider {
public:
    // Responses larger than this are rejected instead of parsed.
    static constexpr std::size_t kMaxResponseBytes = 4 * 1024 * 1024;

    explicit VirusTotalProvider(std::string apiKey);

    [[nodiscard]] std::string_view id() const noexcept override { return "virustotal"; }
    [[nodiscard]] std::string_view displayName() const noexcept override { return "VirusTotal"; }
    [[nodiscard]] std::string disclosure() const override;

    [[nodiscard]] Result<HttpRequest> buildRequest(std::string_view sha256) const override;
    [[nodiscard]] Result<ReputationReport>
    parseResponse(std::string_view sha256, const HttpResponse& response) const override;

private:
    std::string apiKey_;
};

} // namespace sectoryn
