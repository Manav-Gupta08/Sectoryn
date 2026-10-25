#include "detectors/rules/SectionPermissionRule.hpp"

#include "detectors/rules/RuleSupport.hpp"

namespace sectoryn::rules {

RuleOutcome SectionPermissionRule::evaluate(const RuleContext& context,
                                            std::vector<Finding>& findings) const {
    if (!context.image.sectionTable.hasData()) {
        return RuleOutcome::skipped("the section table could not be read");
    }

    reportAnomalies(
        context, {SectionAnomalyKind::WritableAndExecutable},
        {
            .ruleId = "section.writable_executable",
            .title = "Writable and executable section",
            .description = "At least one section is mapped both writable and executable.",
            .severity = Severity::Medium,
            .confidence = Confidence::High,
            .explanation = "Memory that is writable and executable lets a program create or "
                           "modify instructions while it runs. Packers, self-decrypting stubs "
                           "and shellcode loaders depend on this.",
            .limitations = "JIT compilers, some older toolchains and copy-protection schemes "
                           "create such sections too. The flags only describe the initial "
                           "mapping; a program can change protections at run time either way.",
            .attack = {{"T1027.002", "Obfuscated Files or Information: Software Packing"}},
            .nextStep = "Check the section's entropy and whether the entry point lies in it. "
                        "If both point to packing, unpack the file or observe it in an isolated "
                        "sandbox.",
            .correlationGroup = "packing",
        },
        findings);

    reportAnomalies(
        context, {SectionAnomalyKind::ExecutableWithoutCodeFlag},
        {
            .ruleId = "section.executable_without_code_flag",
            .title = "Executable section not marked as code",
            .description = "At least one section is executable but lacks the CNT_CODE flag.",
            .severity = Severity::Low,
            .confidence = Confidence::High,
            .explanation = "Compilers mark code sections with CNT_CODE. An executable section "
                           "without it is more often produced by a packer or by hand.",
            .limitations = "The flag has no effect on execution, and some linkers and "
                           "protectors set it inconsistently.",
            .attack = {},
            .nextStep = "Disassemble the section to see whether it holds ordinary code or an "
                        "unpacking stub.",
            .correlationGroup = "packing",
        },
        findings);

    reportAnomalies(
        context, {SectionAnomalyKind::SharedAndWritable},
        {
            .ruleId = "section.shared_writable",
            .title = "Shared writable section",
            .description = "At least one section is shared between processes and writable.",
            .severity = Severity::Low,
            .confidence = Confidence::High,
            .explanation = "Every process that loads the image sees the same copy of a shared "
                           "section, so one process can change data another relies on.",
            .limitations = "Some legitimate DLLs keep inter-process state in shared sections.",
            .attack = {},
            .nextStep = "Determine which processes load this image and what the shared data "
                        "is used for.",
            .correlationGroup = {},
        },
        findings);

    return RuleOutcome::ran();
}

} // namespace sectoryn::rules
