#include "engine/signature/SignatureEnrichment.hpp"

#include <format>
#include <string>
#include <utility>

namespace sectoryn {

namespace {

Finding brokenSignature(const SignatureVerification& verification) {
    Finding finding;
    finding.ruleId = "signature.invalid";
    finding.title = "Authenticode signature does not verify";
    finding.description = std::format("The file is signed, but {}.", verification.detail);
    finding.severity = Severity::Medium;
    finding.confidence = Confidence::High;
    finding.evidence.push_back({.description = verification.detail,
                                .fileOffset = std::nullopt,
                                .location = "certificate table"});
    finding.explanation = "A signature that no longer matches the file means the file was "
                          "changed after signing, for example patched or with a payload added.";
    finding.limitations = "Corruption during download or storage produces the same result.";
    finding.nextStep = "Obtain the file from its publisher and compare hashes.";
    finding.correlationGroup = "signature";
    return finding;
}

Finding untrustedSignature(const SignatureVerification& verification) {
    Finding finding;
    finding.ruleId = "signature.untrusted";
    finding.title = "Authenticode signature is not trusted";
    finding.description = std::format("The signature is intact, but {}.", verification.detail);
    finding.severity = Severity::Low;
    finding.confidence = Confidence::Medium;
    finding.evidence.push_back({.description = verification.signer.empty()
                                                   ? verification.detail
                                                   : "signed by " + verification.signer,
                                .fileOffset = std::nullopt,
                                .location = "certificate table"});
    finding.explanation = "Self-signed, expired and revoked certificates are common in "
                          "unwanted software, which cannot obtain a trusted one.";
    finding.limitations = "In-house tools, test builds and old software that outlived its "
                          "certificate are untrusted for harmless reasons. Revocation is only "
                          "known if Windows had it cached.";
    finding.nextStep = "Check who issued the certificate and whether the signer is expected.";
    finding.correlationGroup = "signature";
    return finding;
}

} // namespace

EnrichmentResult signatureResult(const SignatureVerification& verification,
                                 std::string_view verifierName) {
    EnrichmentResult result;
    result.id = "signature";
    result.displayName = "Authenticode signature";
    result.version = std::string(verifierName);
    result.status = verification.state == SignatureState::Unavailable
                        ? FieldStatus::incomplete(verification.detail)
                        : FieldStatus::present();
    result.properties.push_back(
        {.name = "State", .value = std::string(toString(verification.state))});
    result.properties.push_back({.name = "Detail", .value = verification.detail});
    if (!verification.signer.empty()) {
        result.properties.push_back({.name = "Signer", .value = verification.signer});
    }
    if (!verification.issuer.empty()) {
        result.properties.push_back({.name = "Issuer", .value = verification.issuer});
    }
    if (!verification.serialNumber.empty()) {
        result.properties.push_back({.name = "Serial number", .value = verification.serialNumber});
    }
    result.properties.push_back(
        {.name = "Revocation",
         .value = verification.usedCachedRevocationOnly ? "cached data only" : "online"});

    if (verification.state == SignatureState::Invalid) {
        result.findings.push_back(brokenSignature(verification));
    } else if (verification.state == SignatureState::Untrusted) {
        result.findings.push_back(untrustedSignature(verification));
    }
    return result;
}

SignatureEnrichment::SignatureEnrichment(std::shared_ptr<const ISignatureVerifier> verifier)
    : verifier_(std::move(verifier)) {}

EnrichmentResult SignatureEnrichment::run(const EnrichmentInput& input,
                                          const CancellationToken& token) const {
    // Without a certificate table there is nothing to verify, and WinVerifyTrust would only
    // repeat that.
    if (input.image.certificate.status.state == FieldState::Absent) {
        SignatureVerification unsignedFile;
        unsignedFile.state = SignatureState::Unsigned;
        unsignedFile.detail = "the file has no certificate table";
        return signatureResult(unsignedFile, verifier_->name());
    }
    return signatureResult(verifier_->verify(input.path, token), verifier_->name());
}

} // namespace sectoryn
