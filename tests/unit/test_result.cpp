#include "core/Error.hpp"
#include "core/Result.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <variant>

namespace sectoryn {
namespace {

Result<int> parsePositive(int value) {
    if (value <= 0) {
        return Error{ErrorCode::InvalidInput, "value must be positive"};
    }
    return value;
}

TEST(Result, HoldsValue) {
    const Result<int> result = parsePositive(7);
    ASSERT_TRUE(result.hasValue());
    EXPECT_TRUE(static_cast<bool>(result));
    EXPECT_EQ(result.value(), 7);
}

TEST(Result, HoldsError) {
    const Result<int> result = parsePositive(-1);
    ASSERT_FALSE(result.hasValue());
    EXPECT_EQ(result.error().code, ErrorCode::InvalidInput);
    EXPECT_EQ(result.error().message, "value must be positive");
}

TEST(Result, ValueOnErrorThrows) {
    const Result<int> result = parsePositive(0);
    EXPECT_THROW(static_cast<void>(result.value()), std::bad_variant_access);
}

TEST(Result, ValueOrReturnsFallbackOnError) {
    EXPECT_EQ(parsePositive(-5).valueOr(42), 42);
    EXPECT_EQ(parsePositive(5).valueOr(42), 5);
}

TEST(Result, SupportsMoveOnlyTypes) {
    Result<std::unique_ptr<int>> result = std::make_unique<int>(3);
    ASSERT_TRUE(result.hasValue());
    const std::unique_ptr<int> owned = std::move(result).value();
    ASSERT_NE(owned, nullptr);
    EXPECT_EQ(*owned, 3);
}

TEST(Result, VoidResultDefaultsToSuccess) {
    const Status ok;
    EXPECT_TRUE(ok.hasValue());

    const Status failed = Error{ErrorCode::Cancelled, "stopped by user"};
    ASSERT_FALSE(failed.hasValue());
    EXPECT_EQ(failed.error().code, ErrorCode::Cancelled);
}

TEST(Error, DescribeIncludesCategoryAndMessage) {
    const Error error{ErrorCode::ResourceLimitExceeded, "file exceeds 256 MiB"};
    EXPECT_EQ(error.describe(), "resource limit exceeded: file exceeds 256 MiB");
    EXPECT_EQ(Error(ErrorCode::IoFailure, "").describe(), "I/O failure");
}

TEST(Error, EveryCodeHasName) {
    for (const ErrorCode code :
         {ErrorCode::InvalidInput, ErrorCode::UnsupportedFormat, ErrorCode::MalformedData,
          ErrorCode::ParserFailure, ErrorCode::Cancelled, ErrorCode::ResourceLimitExceeded,
          ErrorCode::IoFailure, ErrorCode::ExternalServiceFailure, ErrorCode::Internal}) {
        EXPECT_FALSE(toString(code).empty());
        EXPECT_NE(toString(code), "unknown error");
    }
}

} // namespace
} // namespace sectoryn
