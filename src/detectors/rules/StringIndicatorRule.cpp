#include "detectors/rules/StringIndicatorRule.hpp"

#include "detectors/rules/RuleSupport.hpp"

#include <algorithm>
#include <format>
#include <initializer_list>
#include <utility>

namespace sectoryn::rules {

namespace {

void report(const std::vector<Indicator>& indicators, std::initializer_list<IndicatorKind> kinds,
            Finding prototype, std::vector<Finding>& findings) {
    std::size_t matches = 0;
    for (const Indicator& indicator : indicators) {
        if (std::ranges::find(kinds, indicator.kind) == kinds.end()) {
            continue;
        }
        ++matches;
        addEvidence(prototype, {.description = std::format("{}: {}", toString(indicator.kind),
                                                           indicator.value),
                                .fileOffset = indicator.offset,
                                .location = "strings"});
    }
    if (matches == 0) {
        return;
    }
    if (matches > prototype.evidence.size()) {
        prototype.description += std::format(" {} matches in total; the first {} are listed.",
                                             matches, prototype.evidence.size());
    }
    findings.push_back(std::move(prototype));
}

} // namespace

RuleOutcome StringIndicatorRule::evaluate(const RuleContext& context,
                                          std::vector<Finding>& findings) const {
    if (context.indicators == nullptr || context.strings == nullptr) {
        return RuleOutcome::skipped("strings were not extracted");
    }
    const std::vector<Indicator>& indicators = *context.indicators;
    const std::string coverage = context.strings->limitReached
                                     ? " String extraction stopped at a configured limit, so "
                                       "further matches may exist."
                                     : "";

    report(indicators, {IndicatorKind::PowerShell},
           {
               .ruleId = "strings.powershell",
               .title = "PowerShell command fragments",
               .description = "The file contains PowerShell commands or options.",
               .severity = Severity::Medium,
               .confidence = Confidence::Medium,
               .explanation = "Encoded commands, download cradles and execution-policy bypasses "
                              "are common in droppers that hand off to PowerShell.",
               .limitations = "Administration tools and installers embed PowerShell legitimately. "
                              "A string may be present without ever being executed." +
                              coverage,
               .attack = {{"T1059.001", "Command and Scripting Interpreter: PowerShell"}},
               .nextStep = "Decode any encoded command and review what it would do.",
               .correlationGroup = "script_execution",
           },
           findings);

    report(indicators, {IndicatorKind::CommandLine},
           {
               .ruleId = "strings.command_line",
               .title = "Command-line tool usage",
               .description = "The file contains command lines for system utilities that are "
                              "often misused.",
               .severity = Severity::Low,
               .confidence = Confidence::Medium,
               .explanation = "Tools such as cmd, rundll32, regsvr32, mshta, certutil and vssadmin "
                              "let a program act through trusted system binaries.",
               .limitations = "Installers and administration tools use the same utilities for "
                              "ordinary tasks." +
                              coverage,
               .attack = {{"T1059.003", "Command and Scripting Interpreter: Windows Command Shell"},
                          {"T1218", "System Binary Proxy Execution"}},
               .nextStep = "Reconstruct the full command lines and check what they act on.",
               .correlationGroup = "script_execution",
           },
           findings);

    report(indicators, {IndicatorKind::Persistence},
           {
               .ruleId = "strings.persistence",
               .title = "References to autostart locations",
               .description = "The file names registry keys, folders or commands used to start "
                              "programs automatically.",
               .severity = Severity::Medium,
               .confidence = Confidence::Low,
               .explanation = "Writing to Run keys, scheduled tasks or service keys makes a "
                              "program survive reboots.",
               .limitations = "Legitimate software registers itself for autostart too, and "
                              "security tools reference these locations to inspect them." +
                              coverage,
               .attack = {{"T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / "
                                        "Startup Folder"},
                          {"T1053.005", "Scheduled Task/Job: Scheduled Task"}},
               .nextStep = "Check whether code that writes these locations is reachable, for "
                           "example via registry or task scheduler imports.",
               .correlationGroup = "persistence",
           },
           findings);

    report(indicators, {IndicatorKind::EncodedData},
           {
               .ruleId = "strings.encoded_data",
               .title = "Embedded encoded data",
               .description = "The file contains long base64-like strings.",
               .severity = Severity::Low,
               .confidence = Confidence::Low,
               .explanation = "Encoding hides configuration, scripts or payloads from simple "
                              "string searches.",
               .limitations = "Certificates, images, license keys and serialized data are often "
                              "stored as base64." +
                              coverage,
               .attack = {{"T1027", "Obfuscated Files or Information"}},
               .nextStep = "Decode the strings and analyze the result.",
               .correlationGroup = "obfuscation",
           },
           findings);

    report(indicators,
           {IndicatorKind::Url, IndicatorKind::Domain, IndicatorKind::IpV4Address,
            IndicatorKind::UncPath},
           {
               .ruleId = "strings.network",
               .title = "Network indicators",
               .description = "The file contains URLs, host names or IP addresses.",
               .severity = Severity::Informational,
               .confidence = Confidence::High,
               .explanation = "Embedded addresses can identify download locations or command "
                              "and control servers.",
               .limitations = "Most software contains benign addresses, for example certificate "
                              "revocation, update and documentation URLs. Presence says nothing "
                              "about whether the address is contacted." +
                              coverage,
               .attack = {},
               .nextStep = "Check the addresses against threat intelligence and look for the "
                           "code that uses them.",
               .correlationGroup = {},
           },
           findings);

    report(indicators, {IndicatorKind::FilePath, IndicatorKind::RegistryKey},
           {
               .ruleId = "strings.paths",
               .title = "File paths and registry keys",
               .description = "The file contains file system paths or registry keys.",
               .severity = Severity::Informational,
               .confidence = Confidence::High,
               .explanation = "Paths and keys show where a program may read or write and can be "
                              "used as host-based indicators.",
               .limitations = "Almost every program contains such strings." + coverage,
               .attack = {},
               .nextStep = "Look for paths in user-writable or system locations that the "
                           "program has no obvious reason to touch.",
               .correlationGroup = {},
           },
           findings);

    return RuleOutcome::ran();
}

} // namespace sectoryn::rules
