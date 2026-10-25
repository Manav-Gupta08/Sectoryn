#include "detectors/rules/EntropyRule.hpp"

#include "detectors/rules/RuleSupport.hpp"

#include <format>
#include <utility>

namespace sectoryn::rules {

namespace {

// The certificate table is DER data with naturally high entropy; an overlay that is little
// more than the signature says nothing about hidden payloads.
constexpr std::uint64_t kCertificateSlack = 8;

bool isHigh(const RangeEntropy& range) {
    return range.entropy.has_value() && *range.entropy >= EntropyRule::kHighEntropy &&
           range.bytes >= EntropyRule::kMinBytes;
}

} // namespace

RuleOutcome EntropyRule::evaluate(const RuleContext& context,
                                  std::vector<Finding>& findings) const {
    if (context.entropy == nullptr) {
        return RuleOutcome::skipped("entropy was not computed");
    }
    const EntropyReport& report = *context.entropy;

    Finding packedCode{
        .ruleId = "entropy.packed_code",
        .title = "High-entropy executable section",
        .description = std::format("Executable sections have entropy of at least {:.1f} bits "
                                   "per byte.",
                                   kHighEntropy),
        .severity = Severity::Medium,
        .confidence = Confidence::Medium,
        .explanation = "Compiled code rarely exceeds about 6.8 bits per byte. Higher values in "
                       "an executable section usually mean the code is compressed or encrypted "
                       "and unpacked at run time.",
        .limitations = "Code sections that embed large compressed tables or data blobs can "
                       "reach similar values.",
        .attack = {{"T1027.002", "Obfuscated Files or Information: Software Packing"}},
        .nextStep = "Look for an unpacking stub at the entry point; unpack the file or analyze "
                    "it dynamically in isolation.",
        .correlationGroup = "packing",
    };
    Finding highData{
        .ruleId = "entropy.high_section",
        .title = "High-entropy data section",
        .description = std::format("Non-executable sections have entropy of at least {:.1f} "
                                   "bits per byte.",
                                   kHighEntropy),
        .severity = Severity::Low,
        .confidence = Confidence::Low,
        .explanation = "Compressed or encrypted data in a data section can be a payload that "
                       "is decrypted at run time.",
        .limitations = "Images, icons, compressed resources and certificates are equally "
                       "dense. This is common in benign software.",
        .attack = {},
        .nextStep = "Check what the section holds, for example by looking at its resources or "
                    "at the code that references it.",
        .correlationGroup = "high_entropy_data",
    };

    for (std::size_t i = 0; i < report.sections.size() && i < context.sections.sections.size();
         ++i) {
        if (!isHigh(report.sections[i])) {
            continue;
        }
        const bool executable = context.sections.sections[i].flags.execute;
        Finding& target = executable ? packedCode : highData;
        addEvidence(target, sectionEvidence(context.image, i,
                                            std::format("entropy {:.2f} over {} bytes",
                                                        *report.sections[i].entropy,
                                                        report.sections[i].bytes)));
    }
    if (!packedCode.evidence.empty()) {
        findings.push_back(std::move(packedCode));
    }
    if (!highData.evidence.empty()) {
        findings.push_back(std::move(highData));
    }

    const Overlay& overlay = context.image.overlay;
    const bool onlySignature = overlay.containsCertificateTable &&
                               overlay.size <= context.image.certificate.size + kCertificateSlack;
    if (isHigh(report.overlay) && !onlySignature) {
        findings.push_back({
            .ruleId = "entropy.high_overlay",
            .title = "High-entropy overlay",
            .description = std::format("{} bytes are appended after the last section with "
                                       "entropy {:.2f}.",
                                       report.overlay.bytes, *report.overlay.entropy),
            .severity = Severity::Low,
            .confidence = Confidence::Low,
            .evidence = {{.description = "overlay",
                          .fileOffset = overlay.fileOffset,
                          .location = "overlay"}},
            .explanation = "Data appended to an executable is not mapped by the loader. Droppers "
                           "use it to carry an encrypted payload.",
            .limitations = "Installers, self-extracting archives and signed files routinely "
                           "carry compressed data or signatures in the overlay.",
            .attack = {{"T1027.009", "Obfuscated Files or Information: Embedded Payloads"}},
            .nextStep = "Identify the overlay's format and extract it for separate analysis.",
            .correlationGroup = "embedded_payload",
        });
    }
    return RuleOutcome::ran();
}

} // namespace sectoryn::rules
