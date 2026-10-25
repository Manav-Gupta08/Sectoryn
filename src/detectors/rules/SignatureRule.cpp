#include "detectors/rules/SignatureRule.hpp"

#include <cstdint>
#include <format>

namespace sectoryn::rules {

namespace {

// Entries of the certificate table are padded to 8 bytes, so up to 7 bytes may follow it.
constexpr std::uint64_t kCertificateAlignment = 8;

std::uint64_t alignedEnd(const CertificateTable& table) {
    const std::uint64_t end = std::uint64_t{table.fileOffset} + table.size;
    return (end + kCertificateAlignment - 1) / kCertificateAlignment * kCertificateAlignment;
}

} // namespace

RuleOutcome SignatureRule::evaluate(const RuleContext& context,
                                    std::vector<Finding>& findings) const {
    const PeImage& image = context.image;
    const CertificateTable& table = image.certificate;
    if (table.status.state != FieldState::Present) {
        // Absent tables need no layout check; invalid ones are reported as header issues.
        return RuleOutcome::ran();
    }
    if (!image.overlay.status.hasData() && image.overlay.status.state != FieldState::Absent) {
        return RuleOutcome::skipped("the end of the image data is unknown");
    }

    const std::uint64_t end = alignedEnd(table);
    if (end < image.fileSize) {
        findings.push_back({
            .ruleId = "signature.data_after_certificate",
            .title = "Data follows the certificate table",
            .description = std::format("{} bytes follow the certificate table, which signing "
                                       "tools place at the very end of the file.",
                                       image.fileSize - end),
            .severity = Severity::Low,
            .confidence = Confidence::Medium,
            .evidence = {{.description = std::format("certificate table ends at {:#x}, file "
                                                     "ends at {:#x}",
                                                     end, image.fileSize),
                          .fileOffset = end,
                          .location = "certificate table"}},
            .explanation = "Bytes appended after signing are a way to attach a payload or "
                           "configuration to a signed file. Depending on how they were added, "
                           "the signature may or may not still verify.",
            .limitations = "Some installers and update tools legitimately append data after "
                           "signing.",
            .attack = {},
            .nextStep = "Inspect the trailing bytes and check whether the signature still "
                        "verifies.",
            .correlationGroup = "signature",
        });
    }

    if (!image.overlay.containsCertificateTable) {
        findings.push_back({
            .ruleId = "signature.certificate_inside_image",
            .title = "Certificate table overlaps image data",
            .description = "The certificate table does not lie after the last section.",
            .severity = Severity::Low,
            .confidence = Confidence::High,
            .evidence = {{.description = std::format("certificate table at {:#x}, {} bytes",
                                                     table.fileOffset, table.size),
                          .fileOffset = table.fileOffset,
                          .location = "certificate table"}},
            .explanation = "Signing tools append the certificate table after all section "
                           "data. One inside the image was placed there by hand or by a "
                           "tool that rewrote the file.",
            .limitations = "The layout alone does not show whether the signature is valid.",
            .attack = {},
            .nextStep = "Compare the certificate table range with the section table.",
            .correlationGroup = "signature",
        });
    }
    return RuleOutcome::ran();
}

} // namespace sectoryn::rules
