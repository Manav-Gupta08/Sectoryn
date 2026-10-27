#include "reputation/VirusTotalProvider.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <limits>
#include <nlohmann/json.hpp>
#include <utility>

namespace sectoryn {

namespace {

constexpr std::string_view kApiBase = "https://www.virustotal.com/api/v3/files/";
constexpr std::string_view kGuiBase = "https://www.virustotal.com/gui/file/";
constexpr std::size_t kMaxApiKeyLength = 256;

std::string lowercase(std::string_view text) {
    std::string result(text);
    std::ranges::transform(result, result.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

// Keys are sent in a header, so anything but letters and digits is refused outright.
bool isPlausibleApiKey(std::string_view key) {
    return !key.empty() && key.size() <= kMaxApiKeyLength && std::ranges::all_of(key, [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) != 0;
    });
}

std::uint32_t countOf(const nlohmann::json& stats, const char* name) {
    const auto it = stats.find(name);
    if (it == stats.end() || !it->is_number_unsigned()) {
        return 0;
    }
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(
        it->get<std::uint64_t>(), std::numeric_limits<std::uint32_t>::max()));
}

Error serviceError(std::string message) {
    return {ErrorCode::ExternalServiceFailure, std::move(message)};
}

} // namespace

VirusTotalProvider::VirusTotalProvider(std::string apiKey)
    : apiKey_(std::move(apiKey)) {}

std::string VirusTotalProvider::disclosure() const {
    return "The file's SHA-256 hash and your API key are sent over HTTPS to VirusTotal "
           "(www.virustotal.com), a service operated by Google. The file itself is not uploaded. "
           "VirusTotal may log the lookup.";
}

Result<HttpRequest> VirusTotalProvider::buildRequest(std::string_view sha256) const {
    if (!isSha256Hex(sha256)) {
        return Error{ErrorCode::InvalidInput, "not a SHA-256 hash"};
    }
    if (!isPlausibleApiKey(apiKey_)) {
        return Error{ErrorCode::InvalidInput, "the API key must consist of letters and digits"};
    }
    HttpRequest request;
    request.url = std::string(kApiBase) + lowercase(sha256);
    request.headers = {{"x-apikey", apiKey_}, {"accept", "application/json"}};
    return request;
}

Result<ReputationReport> VirusTotalProvider::parseResponse(std::string_view sha256,
                                                           const HttpResponse& response) const {
    ReputationReport report;
    report.provider = std::string(id());
    report.sha256 = lowercase(sha256);
    report.permalink = std::string(kGuiBase) + report.sha256;
    report.retrievedAt = std::chrono::system_clock::now();

    switch (response.status) {
    case 200:
        break;
    case 404:
        return report;
    case 0:
        return serviceError("no response from VirusTotal");
    case 401:
    case 403:
        return serviceError("VirusTotal rejected the API key");
    case 429:
        return serviceError("VirusTotal quota exceeded; try again later");
    default:
        return serviceError(
            std::format("VirusTotal answered with HTTP status {}", response.status));
    }

    if (response.body.size() > kMaxResponseBytes) {
        return serviceError("the VirusTotal response is too large");
    }
    const nlohmann::json json = nlohmann::json::parse(response.body, nullptr, false);
    if (json.is_discarded() || !json.is_object()) {
        return serviceError("the VirusTotal response is not valid JSON");
    }
    const auto data = json.find("data");
    if (data == json.end() || !data->is_object()) {
        return serviceError("the VirusTotal response has no data object");
    }
    if (const auto responseId = data->find("id");
        responseId != data->end() &&
        (!responseId->is_string() || lowercase(responseId->get<std::string>()) != report.sha256)) {
        return serviceError("the VirusTotal response describes a different file");
    }
    const auto attributes = data->find("attributes");
    if (attributes == data->end() || !attributes->is_object()) {
        return serviceError("the VirusTotal response has no attributes");
    }

    report.known = true;
    if (const auto stats = attributes->find("last_analysis_stats");
        stats != attributes->end() && stats->is_object()) {
        report.malicious = countOf(*stats, "malicious");
        report.suspicious = countOf(*stats, "suspicious");
        report.harmless = countOf(*stats, "harmless");
        report.undetected = countOf(*stats, "undetected");
    }
    if (const auto date = attributes->find("last_analysis_date");
        date != attributes->end() && date->is_number_integer()) {
        report.lastAnalysis = date->get<std::int64_t>();
    }
    return report;
}

} // namespace sectoryn
