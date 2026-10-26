#include "detectors/rules/SignatureRule.hpp"
#include "engine/AnalysisEngine.hpp"
#include "engine/signature/SignatureEnrichment.hpp"
#include "parsers/PeConstants.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"

#include <algorithm>
#include <atomic>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

using test::bytesOf;
using test::PeBuilder;

struct LayoutFixture {
    PeImage image;
    SectionAnalysis sections;

    LayoutFixture(std::uint32_t certificateOffset, std::uint32_t certificateSize,
                  std::uint64_t fileSize) {
        image.fileSize = fileSize;
        image.certificate = {FieldStatus::present(), certificateOffset, certificateSize};
        image.overlay = {FieldStatus::present(), 0x1000, fileSize - 0x1000, false};
        image.overlay.containsCertificateTable = certificateOffset >= 0x1000;
    }

    std::vector<Finding> run() const {
        std::vector<Finding> findings;
        const RuleOutcome outcome =
            rules::SignatureRule().evaluate({image, sections, nullptr, nullptr, nullptr}, findings);
        EXPECT_TRUE(outcome.evaluated) << outcome.skipReason;
        return findings;
    }
};

bool hasFinding(const std::vector<Finding>& findings, std::string_view id) {
    return std::ranges::any_of(findings, [&](const Finding& f) { return f.ruleId == id; });
}

TEST(SignatureRule, AcceptsTableAtTheEndOfTheFile) {
    EXPECT_TRUE(LayoutFixture(0x1000, 0x200, 0x1200).run().empty());
}

TEST(SignatureRule, AllowsAlignmentPadding) {
    EXPECT_TRUE(LayoutFixture(0x1000, 0x1FB, 0x1200).run().empty());
}

TEST(SignatureRule, FlagsDataAfterTheTable) {
    const std::vector<Finding> findings = LayoutFixture(0x1000, 0x200, 0x1400).run();
    ASSERT_EQ(findings.size(), 1U);
    EXPECT_EQ(findings[0].ruleId, "signature.data_after_certificate");
    ASSERT_EQ(findings[0].evidence.size(), 1U);
    EXPECT_EQ(findings[0].evidence[0].fileOffset, 0x1200U);
}

TEST(SignatureRule, FlagsTableInsideImageData) {
    EXPECT_TRUE(hasFinding(LayoutFixture(0x800, 0x200, 0x1200).run(),
                           "signature.certificate_inside_image"));
}

TEST(SignatureRule, IgnoresUnsignedAndInvalidTables) {
    LayoutFixture unsignedFile(0, 0, 0x1200);
    unsignedFile.image.certificate.status = FieldStatus::absent("no entry");
    EXPECT_TRUE(unsignedFile.run().empty());

    LayoutFixture invalid(0x5000, 0x200, 0x1200);
    invalid.image.certificate.status = FieldStatus::invalid("past the end");
    EXPECT_TRUE(invalid.run().empty());
}

TEST(SignatureRule, SkipsWhenImageEndIsUnknown) {
    LayoutFixture fixture(0x1000, 0x200, 0x1400);
    fixture.image.overlay.status = {FieldState::NotInspected, "no section table"};
    std::vector<Finding> findings;
    const RuleOutcome outcome = rules::SignatureRule().evaluate(
        {fixture.image, fixture.sections, nullptr, nullptr, nullptr}, findings);
    EXPECT_FALSE(outcome.evaluated);
    EXPECT_TRUE(findings.empty());
}

SignatureVerification verification(SignatureState state) {
    SignatureVerification result;
    result.state = state;
    result.detail = "test detail";
    result.signer = "Example Signer";
    return result;
}

TEST(SignatureResult, OnlyBrokenOrUntrustedSignaturesAreFindings) {
    EXPECT_TRUE(signatureResult(verification(SignatureState::Verified), "test").findings.empty());
    EXPECT_TRUE(signatureResult(verification(SignatureState::Unsigned), "test").findings.empty());

    const EnrichmentResult invalid = signatureResult(verification(SignatureState::Invalid), "t");
    ASSERT_EQ(invalid.findings.size(), 1U);
    EXPECT_EQ(invalid.findings[0].ruleId, "signature.invalid");
    EXPECT_EQ(invalid.findings[0].severity, Severity::Medium);

    const EnrichmentResult untrusted =
        signatureResult(verification(SignatureState::Untrusted), "t");
    ASSERT_EQ(untrusted.findings.size(), 1U);
    EXPECT_EQ(untrusted.findings[0].ruleId, "signature.untrusted");
}

TEST(SignatureResult, UnavailableVerificationIsACoverageGap) {
    const EnrichmentResult result = signatureResult(verification(SignatureState::Unavailable), "t");
    EXPECT_EQ(result.status.state, FieldState::Incomplete);
    EXPECT_TRUE(result.findings.empty());
}

TEST(SignatureResult, ListsSignerProperties) {
    const EnrichmentResult result = signatureResult(verification(SignatureState::Verified), "t");
    EXPECT_TRUE(std::ranges::any_of(result.properties, [](const EnrichmentProperty& p) {
        return p.name == "Signer" && p.value == "Example Signer";
    }));
}

class FakeVerifier final : public ISignatureVerifier {
public:
    explicit FakeVerifier(SignatureState state)
        : state_(state) {}

    [[nodiscard]] std::string_view name() const noexcept override { return "fake"; }
    [[nodiscard]] bool supported() const noexcept override { return true; }
    [[nodiscard]] SignatureVerification verify(const std::filesystem::path&,
                                               const CancellationToken&) const override {
        ++calls;
        return verification(state_);
    }

    mutable std::atomic<int> calls = 0;

private:
    SignatureState state_;
};

std::vector<std::byte> signedLookingPe() {
    PeBuilder builder;
    builder.addSection(".text", PeBuilder::kCode, bytesOf(std::string(0x200, '\xC3')))
        .overlay(std::vector<std::byte>(0x100, std::byte{0x30}));
    std::vector<std::byte> file = builder.build();
    const auto offset = static_cast<std::uint32_t>(file.size() - 0x100);
    const std::size_t entry = builder.dataDirectoryOffset(pe::kCertificateDirectory);
    test::writeLe32(file, entry, offset);
    test::writeLe32(file, entry + 4, 0x100);
    return file;
}

TEST(SignatureEnrichment, ReportsBrokenSignaturesThroughTheEngine) {
    auto verifier = std::make_shared<FakeVerifier>(SignatureState::Invalid);
    Result<AnalysisEngine> engine =
        AnalysisEngine::createDefault({}, {std::make_shared<const SignatureEnrichment>(verifier)});
    ASSERT_TRUE(engine.hasValue()) << engine.error().describe();

    const test::TempDir dir;
    const Result<AnalysisResult> result =
        engine.value().analyze(dir.write("signed.exe", signedLookingPe()));
    ASSERT_TRUE(result.hasValue()) << result.error().describe();
    EXPECT_EQ(verifier->calls, 1);
    EXPECT_TRUE(hasFinding(result.value().findings, "signature.invalid"));
    ASSERT_EQ(result.value().enrichments.size(), 1U);
    EXPECT_EQ(result.value().enrichments[0].id, "signature");
}

TEST(SignatureEnrichment, SkipsVerifierForFilesWithoutCertificateTable) {
    auto verifier = std::make_shared<FakeVerifier>(SignatureState::Invalid);
    Result<AnalysisEngine> engine =
        AnalysisEngine::createDefault({}, {std::make_shared<const SignatureEnrichment>(verifier)});
    ASSERT_TRUE(engine.hasValue());

    const test::TempDir dir;
    const std::vector<std::byte> file =
        PeBuilder().addSection(".text", PeBuilder::kCode, bytesOf("\xC3")).build();
    const Result<AnalysisResult> result = engine.value().analyze(dir.write("plain.exe", file));
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(verifier->calls, 0);
    EXPECT_FALSE(hasFinding(result.value().findings, "signature.invalid"));
}

TEST(PlatformSignatureVerifier, AlwaysReturnsAVerifier) {
    const std::unique_ptr<ISignatureVerifier> verifier = createPlatformSignatureVerifier();
    ASSERT_NE(verifier, nullptr);
    if (!verifier->supported()) {
        EXPECT_EQ(verifier->verify("missing.exe", {}).state, SignatureState::Unavailable);
    }
}

} // namespace
} // namespace sectoryn
