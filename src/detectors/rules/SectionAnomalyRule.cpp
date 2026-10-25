#include "detectors/rules/SectionAnomalyRule.hpp"

#include "detectors/rules/RuleSupport.hpp"

namespace sectoryn::rules {

RuleOutcome SectionAnomalyRule::evaluate(const RuleContext& context,
                                         std::vector<Finding>& findings) const {
    if (!context.image.sectionTable.hasData()) {
        return RuleOutcome::skipped("the section table could not be read");
    }

    reportAnomalies(
        context, {SectionAnomalyKind::PackerSectionName},
        {
            .ruleId = "section.packer_name",
            .title = "Section names of a known packer",
            .description = "Section names match those written by a known packer or protector.",
            .severity = Severity::Medium,
            .confidence = Confidence::Medium,
            .explanation = "Packed files keep their real code compressed or encrypted until "
                           "run time, which hides it from static inspection.",
            .limitations = "Packers are also used legitimately to reduce size or protect "
                           "commercial software, and section names are trivial to change or "
                           "imitate.",
            .attack = {{"T1027.002", "Obfuscated Files or Information: Software Packing"}},
            .nextStep = "Identify the packer and unpack the file if possible. Treat other "
                        "static results as incomplete until then.",
            .correlationGroup = "packing",
        },
        findings);

    reportAnomalies(
        context, {SectionAnomalyKind::RawDataOverlap, SectionAnomalyKind::VirtualRangeOverlap},
        {
            .ruleId = "section.overlap",
            .title = "Overlapping sections",
            .description = "Sections share raw file data or virtual address ranges.",
            .severity = Severity::Medium,
            .confidence = Confidence::High,
            .explanation = "Standard linkers never produce overlapping sections. Overlaps are a "
                           "known way to hide data from tools or to make them disagree about "
                           "the file's contents.",
            .limitations = "Some packers and very old linkers produce overlaps for space "
                           "reasons without any intent to evade analysis.",
            .attack = {{"T1027", "Obfuscated Files or Information"}},
            .nextStep = "Compare what each overlapping section contains and check whether the "
                        "loader would accept the file.",
            .correlationGroup = "malformed",
        },
        findings);

    reportAnomalies(
        context, {SectionAnomalyKind::RawDataOutsideFile, SectionAnomalyKind::RawDataTruncated},
        {
            .ruleId = "section.data_outside_file",
            .title = "Section data missing from the file",
            .description = "The section table refers to raw data that is not in the file.",
            .severity = Severity::Low,
            .confidence = Confidence::High,
            .explanation = "The file is truncated or its section table is malformed. Analysis "
                           "of the missing data is impossible.",
            .limitations = "Files damaged in transfer, carved from disk images or dumped from "
                           "memory are often incomplete for innocent reasons.",
            .attack = {},
            .nextStep = "Obtain a complete copy of the file before drawing conclusions.",
            .correlationGroup = "malformed",
        },
        findings);

    reportAnomalies(
        context,
        {SectionAnomalyKind::VirtualAddressOutOfOrder, SectionAnomalyKind::VirtualAddressMisaligned,
         SectionAnomalyKind::RawOffsetMisaligned, SectionAnomalyKind::BeyondSizeOfImage,
         SectionAnomalyKind::RawDataInHeaders},
        {
            .ruleId = "section.layout_inconsistent",
            .title = "Inconsistent section layout",
            .description = "Section addresses, offsets or sizes break the rules of the PE "
                           "format.",
            .severity = Severity::Low,
            .confidence = Confidence::High,
            .explanation = "Hand-crafted or tampered files often break layout rules that "
                           "linkers follow, sometimes to confuse analysis tools.",
            .limitations = "The Windows loader tolerates many of these inconsistencies, and "
                           "some unusual toolchains produce them.",
            .attack = {},
            .nextStep = "Review the section table for signs of manual modification.",
            .correlationGroup = "malformed",
        },
        findings);

    reportAnomalies(context, {SectionAnomalyKind::EmptyName, SectionAnomalyKind::NonPrintableName},
                    {
                        .ruleId = "section.unusual_name",
                        .title = "Unusual section name",
                        .description = "Section names are empty or contain non-printable bytes.",
                        .severity = Severity::Low,
                        .confidence = Confidence::Medium,
                        .explanation = "Compilers write short printable names. Empty or binary "
                                       "names usually come from packers or manual edits.",
                        .limitations = "Names have no effect on loading and some obscure "
                                       "toolchains leave them empty.",
                        .attack = {},
                        .nextStep = "Inspect the affected sections' contents and permissions.",
                        .correlationGroup = "packing",
                    },
                    findings);

    return RuleOutcome::ran();
}

} // namespace sectoryn::rules
