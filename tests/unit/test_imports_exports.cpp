#include "parsers/LiefPeParser.hpp"
#include "support/PeBuilder.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

using test::bytesOf;
using test::PeBuilder;

Result<PeImage> parsePe(const std::vector<std::byte>& file, const AnalysisLimits& limits = {}) {
    return LiefPeParser{}.parse(file, limits, {});
}

PeBuilder withCode(PeFormat format = PeFormat::Pe32) {
    PeBuilder builder(format);
    builder.addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x40, '\xC3')));
    return builder;
}

std::vector<std::string> functionNames(const ImportedModule& imported) {
    std::vector<std::string> names;
    for (const ImportedFunction& function : imported.functions) {
        names.push_back(function.name);
    }
    return names;
}

class ImportFormats : public ::testing::TestWithParam<PeFormat> {};

TEST_P(ImportFormats, ParsesNamedAndOrdinalImports) {
    const auto file = withCode(GetParam())
                          .addImport("KERNEL32.dll", {"CreateFileW", "ReadFile", "#17"})
                          .addImport("USER32.dll", {"MessageBoxW"})
                          .build();
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const ImportTable& imports = result.value().imports;

    EXPECT_EQ(imports.status.state, FieldState::Present) << imports.status.detail;
    EXPECT_EQ(imports.delayStatus.state, FieldState::Absent);
    ASSERT_EQ(imports.modules.size(), 2U);

    const ImportedModule& kernel32 = imports.modules[0];
    EXPECT_EQ(kernel32.name, "KERNEL32.dll");
    EXPECT_FALSE(kernel32.delayLoaded);
    ASSERT_EQ(kernel32.functions.size(), 3U);
    EXPECT_EQ(kernel32.functions[0].name, "CreateFileW");
    EXPECT_FALSE(kernel32.functions[0].ordinal.has_value());
    EXPECT_EQ(kernel32.functions[1].name, "ReadFile");
    EXPECT_TRUE(kernel32.functions[2].name.empty());
    EXPECT_EQ(kernel32.functions[2].ordinal, 17);

    EXPECT_EQ(imports.modules[1].name, "USER32.dll");
    EXPECT_EQ(functionNames(imports.modules[1]), (std::vector<std::string>{"MessageBoxW"}));
    EXPECT_TRUE(result.value().issues.empty());
}

INSTANTIATE_TEST_SUITE_P(PeFormats, ImportFormats,
                         ::testing::Values(PeFormat::Pe32, PeFormat::Pe32Plus),
                         [](const ::testing::TestParamInfo<PeFormat>& param) {
                             return param.param == PeFormat::Pe32 ? "Pe32" : "Pe32Plus";
                         });

TEST(Imports, ParsesDelayLoadImports) {
    const auto file = withCode()
                          .addImport("KERNEL32.dll", {"Sleep"})
                          .addDelayImport("WININET.dll", {"InternetOpenA", "InternetOpenUrlA"})
                          .build();
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const ImportTable& imports = result.value().imports;

    EXPECT_EQ(imports.delayStatus.state, FieldState::Present) << imports.delayStatus.detail;
    ASSERT_EQ(imports.modules.size(), 2U);
    const ImportedModule& wininet = imports.modules[1];
    EXPECT_EQ(wininet.name, "WININET.dll");
    EXPECT_TRUE(wininet.delayLoaded);
    EXPECT_EQ(functionNames(wininet),
              (std::vector<std::string>{"InternetOpenA", "InternetOpenUrlA"}));
}

TEST(Imports, LimitsModules) {
    AnalysisLimits limits;
    limits.maxImportedModules = 1;
    const auto file =
        withCode().addImport("A.dll", {"One"}).addImport("B.dll", {"Two"}).build();
    const Result<PeImage> result = parsePe(file, limits);
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().imports.modules.size(), 1U);
    EXPECT_EQ(result.value().imports.status.state, FieldState::Incomplete);
}

TEST(Imports, LimitsFunctions) {
    AnalysisLimits limits;
    limits.maxImportedFunctions = 2;
    const auto file = withCode().addImport("A.dll", {"One", "Two", "Three"}).build();
    const Result<PeImage> result = parsePe(file, limits);
    ASSERT_TRUE(result.hasValue());
    ASSERT_EQ(result.value().imports.modules.size(), 1U);
    EXPECT_EQ(result.value().imports.modules[0].functions.size(), 2U);
    EXPECT_EQ(result.value().imports.status.state, FieldState::Incomplete);
}

TEST(Imports, DeclaredButUnreadableDirectoryIsNotAbsent) {
    PeBuilder builder = withCode();
    auto file = builder.build();
    // Point the import directory at zeros inside .text: declared, yet nothing to read.
    test::writeLe32(file, builder.dataDirectoryOffset(1), 0x1000);
    test::writeLe32(file, builder.dataDirectoryOffset(1) + 4, 40);
    const auto padding = std::vector<std::byte>(0x40, std::byte{0});
    std::ranges::copy(padding, file.begin() + 0x200);

    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().imports.status.state, FieldState::ParserError);
}

TEST(Exports, ParsesNamedExports) {
    const auto file = withCode()
                          .characteristics(0x2102)
                          .exports("sample.dll", {"Run", "Alpha"})
                          .build();
    const Result<PeImage> result = parsePe(file);
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    const ExportTable& exports = result.value().exports;

    EXPECT_EQ(exports.status.state, FieldState::Present) << exports.status.detail;
    EXPECT_EQ(exports.dllName, "sample.dll");
    EXPECT_EQ(exports.ordinalBase, 1U);
    ASSERT_EQ(exports.functions.size(), 2U);
    EXPECT_EQ(exports.functions[0].name, "Alpha");
    EXPECT_EQ(exports.functions[0].ordinal, 1U);
    EXPECT_EQ(exports.functions[0].rva, 0x1000U);
    EXPECT_FALSE(exports.functions[0].forwarder.has_value());
    EXPECT_EQ(exports.functions[1].name, "Run");
    EXPECT_EQ(exports.functions[1].ordinal, 2U);
    EXPECT_EQ(exports.functions[1].rva, 0x1010U);
    EXPECT_TRUE(result.value().issues.empty());
}

TEST(Exports, LimitsExports) {
    AnalysisLimits limits;
    limits.maxExports = 1;
    const auto file = withCode().exports("sample.dll", {"A", "B", "C"}).build();
    const Result<PeImage> result = parsePe(file, limits);
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().exports.functions.size(), 1U);
    EXPECT_EQ(result.value().exports.status.state, FieldState::Incomplete);
}

TEST(Exports, MissingExportTableIsAbsent) {
    const Result<PeImage> result = parsePe(withCode().build());
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result.value().exports.status.state, FieldState::Absent);
    EXPECT_TRUE(result.value().exports.functions.empty());
}

} // namespace
} // namespace sectoryn
