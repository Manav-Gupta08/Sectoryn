#include "reputation/RateLimiter.hpp"
#include "reputation/ReputationCache.hpp"
#include "reputation/VirusTotalProvider.hpp"

#include <cctype>
#include <gtest/gtest.h>
#include <string>

namespace sectoryn {
namespace {

using namespace std::chrono_literals;

const std::string kHash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

TEST(Sha256Hex, AcceptsOnlySixtyFourHexDigits) {
    EXPECT_TRUE(isSha256Hex(kHash));
    EXPECT_TRUE(isSha256Hex(std::string(64, 'A')));
    EXPECT_FALSE(isSha256Hex(kHash.substr(1)));
    EXPECT_FALSE(isSha256Hex(std::string(63, 'a') + "g"));
    EXPECT_FALSE(isSha256Hex(""));
}

TEST(VirusTotalProvider, BuildsHashOnlyRequest) {
    const VirusTotalProvider provider("abc123");
    const Result<HttpRequest> request = provider.buildRequest(kHash);
    ASSERT_TRUE(request.hasValue()) << request.error().describe();
    EXPECT_EQ(request.value().url, "https://www.virustotal.com/api/v3/files/" + kHash);
    ASSERT_FALSE(request.value().headers.empty());
    EXPECT_EQ(request.value().headers[0].first, "x-apikey");
    EXPECT_EQ(request.value().headers[0].second, "abc123");
}

TEST(VirusTotalProvider, RefusesBadHashesAndKeys) {
    EXPECT_FALSE(VirusTotalProvider("abc").buildRequest("../../etc").hasValue());
    EXPECT_FALSE(VirusTotalProvider("").buildRequest(kHash).hasValue());
    EXPECT_FALSE(VirusTotalProvider("abc\r\nX-Injected: 1").buildRequest(kHash).hasValue());
}

TEST(VirusTotalProvider, ParsesAnalysisStatistics) {
    const std::string body = R"({"data": {"id": ")" + kHash + R"(", "type": "file",
        "attributes": {"last_analysis_date": 1700000000,
        "last_analysis_stats": {"malicious": 3, "suspicious": 1, "harmless": 0,
                                "undetected": 60, "timeout": 2}}}})";
    const Result<ReputationReport> report =
        VirusTotalProvider("k").parseResponse(kHash, {200, body, std::nullopt});
    ASSERT_TRUE(report.hasValue()) << report.error().describe();
    EXPECT_TRUE(report.value().known);
    EXPECT_EQ(report.value().malicious, 3U);
    EXPECT_EQ(report.value().suspicious, 1U);
    EXPECT_EQ(report.value().undetected, 60U);
    EXPECT_EQ(report.value().lastAnalysis, 1700000000);
    EXPECT_EQ(report.value().permalink, "https://www.virustotal.com/gui/file/" + kHash);
}

TEST(VirusTotalProvider, UnknownHashIsNotAnError) {
    const Result<ReputationReport> report =
        VirusTotalProvider("k").parseResponse(kHash, {404, R"({"error": {}})", std::nullopt});
    ASSERT_TRUE(report.hasValue());
    EXPECT_FALSE(report.value().known);
    EXPECT_EQ(report.value().malicious, 0U);
}

TEST(VirusTotalProvider, ReportsServiceErrors) {
    const VirusTotalProvider provider("k");
    for (const int status : {0, 401, 403, 429, 500}) {
        const Result<ReputationReport> report = provider.parseResponse(kHash, {status, "", {}});
        ASSERT_FALSE(report.hasValue()) << status;
        EXPECT_EQ(report.error().code, ErrorCode::ExternalServiceFailure);
    }
}

TEST(VirusTotalProvider, RejectsMalformedOrMismatchedResponses) {
    const VirusTotalProvider provider("k");
    EXPECT_FALSE(provider.parseResponse(kHash, {200, "not json", {}}).hasValue());
    EXPECT_FALSE(provider.parseResponse(kHash, {200, "[]", {}}).hasValue());
    EXPECT_FALSE(provider.parseResponse(kHash, {200, R"({"data": 5})", {}}).hasValue());
    const std::string other =
        R"({"data": {"id": ")" + std::string(64, 'b') + R"(", "attributes": {}}})";
    EXPECT_FALSE(provider.parseResponse(kHash, {200, other, {}}).hasValue());
    const std::string huge(VirusTotalProvider::kMaxResponseBytes + 1, ' ');
    EXPECT_FALSE(provider.parseResponse(kHash, {200, huge, {}}).hasValue());
}

TEST(VirusTotalProvider, IgnoresFieldsOfTheWrongType) {
    const std::string body = R"({"data": {"attributes": {"last_analysis_date": "yesterday",
        "last_analysis_stats": {"malicious": -4, "harmless": "many"}}}})";
    const Result<ReputationReport> report =
        VirusTotalProvider("k").parseResponse(kHash, {200, body, {}});
    ASSERT_TRUE(report.hasValue());
    EXPECT_EQ(report.value().malicious, 0U);
    EXPECT_EQ(report.value().harmless, 0U);
    EXPECT_FALSE(report.value().lastAnalysis.has_value());
}

ReputationReport reportFor(std::string sha256, ReputationCache::Clock::time_point when) {
    ReputationReport report;
    report.provider = "test";
    report.sha256 = std::move(sha256);
    report.retrievedAt = when;
    return report;
}

TEST(ReputationCache, ReturnsFreshEntriesOnly) {
    const auto now = ReputationCache::Clock::now();
    ReputationCache cache(4, 1h);
    cache.store(reportFor(kHash, now));
    EXPECT_TRUE(cache.find("test", kHash, now + 30min).has_value());
    EXPECT_FALSE(cache.find("other", kHash, now).has_value());
    EXPECT_FALSE(cache.find("test", kHash, now + 2h).has_value());
    EXPECT_EQ(cache.size(), 0U);
}

TEST(ReputationCache, LookupIgnoresHashCase) {
    const auto now = ReputationCache::Clock::now();
    ReputationCache cache(4, 1h);
    cache.store(reportFor(kHash, now));
    std::string upper = kHash;
    for (char& c : upper) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    EXPECT_TRUE(cache.find("test", upper, now).has_value());
}

TEST(ReputationCache, EvictsLeastRecentlyUsed) {
    const auto now = ReputationCache::Clock::now();
    ReputationCache cache(2, 1h);
    cache.store(reportFor("a", now));
    cache.store(reportFor("b", now));
    EXPECT_TRUE(cache.find("test", "a", now).has_value());
    cache.store(reportFor("c", now));
    EXPECT_EQ(cache.size(), 2U);
    EXPECT_TRUE(cache.find("test", "a", now).has_value());
    EXPECT_FALSE(cache.find("test", "b", now).has_value());
    EXPECT_TRUE(cache.find("test", "c", now).has_value());
}

TEST(ReputationCache, CapacityIsBounded) {
    ReputationCache cache(ReputationCache::kMaxCapacity * 10, 1h);
    const auto now = ReputationCache::Clock::now();
    for (std::size_t i = 0; i < ReputationCache::kMaxCapacity + 5; ++i) {
        cache.store(reportFor(std::to_string(i), now));
    }
    EXPECT_EQ(cache.size(), ReputationCache::kMaxCapacity);
}

TEST(RateLimiter, SpacesRequestsWithinTheWindow) {
    RateLimiter limiter(2, 60s);
    const auto start = RateLimiter::Clock::time_point{} + 1000h;
    EXPECT_EQ(limiter.delayBeforeNext(start), 0ms);
    limiter.record(start);
    limiter.record(start + 10s);
    EXPECT_EQ(limiter.delayBeforeNext(start + 20s), 40s);
    EXPECT_EQ(limiter.delayBeforeNext(start + 60s), 0ms);
    limiter.record(start + 60s);
    EXPECT_EQ(limiter.delayBeforeNext(start + 61s), 9s);
}

TEST(RetryPolicy, RetriesTransientFailuresAFewTimes) {
    const RetryPolicy policy;
    const HttpResponse busy{503, "", std::nullopt};
    EXPECT_EQ(policy.nextDelay(1, busy), 2000ms);
    EXPECT_EQ(policy.nextDelay(2, busy), 4000ms);
    EXPECT_FALSE(policy.nextDelay(3, busy).has_value());
}

TEST(RetryPolicy, DoesNotRetryFinalAnswers) {
    const RetryPolicy policy;
    for (const int status : {200, 401, 403, 404}) {
        EXPECT_FALSE(policy.nextDelay(1, {status, "", std::nullopt}).has_value()) << status;
    }
}

TEST(RetryPolicy, HonoursRetryAfterWithinLimit) {
    const RetryPolicy policy;
    EXPECT_EQ(policy.nextDelay(1, {429, "", 10s}), 10000ms);
    EXPECT_FALSE(policy.nextDelay(1, {429, "", 3600s}).has_value());
}

} // namespace
} // namespace sectoryn
