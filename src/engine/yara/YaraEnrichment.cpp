#include "engine/yara/YaraEnrichment.hpp"

#include <algorithm>
#include <cctype>
#include <format>
#include <optional>
#include <string>
#include <utility>

namespace sectoryn {

namespace {

std::string lowercase(std::string_view text) {
    std::string result(text);
    std::ranges::transform(result, result.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

const std::string* metadata(const YaraMatch& match, std::string_view name) {
    for (const YaraMetadata& entry : match.metadata) {
        if (lowercase(entry.name) == name) {
            return &entry.value;
        }
    }
    return nullptr;
}

// Rule authors commonly state severity in metadata; anything unrecognized falls back to medium.
Severity severityOf(const YaraMatch& match) {
    const std::string* value = metadata(match, "severity");
    if (value == nullptr) {
        return Severity::Medium;
    }
    const std::string level = lowercase(*value);
    if (level == "informational" || level == "info") {
        return Severity::Informational;
    }
    if (level == "low") {
        return Severity::Low;
    }
    if (level == "high") {
        return Severity::High;
    }
    if (level == "critical") {
        return Severity::Critical;
    }
    return Severity::Medium;
}

bool isTechniqueId(std::string_view token) {
    const auto digits = [](std::string_view text) {
        return std::ranges::all_of(text, [](unsigned char c) { return std::isdigit(c) != 0; });
    };
    if (token.size() == 5) {
        return token[0] == 'T' && digits(token.substr(1));
    }
    return token.size() == 9 && token[0] == 'T' && digits(token.substr(1, 4)) &&
           token[5] == '.' && digits(token.substr(6));
}

// Technique IDs such as "T1055" or "T1055.012" listed in a mitre_attack metadata value.
std::vector<AttackTechnique> techniquesOf(const YaraMatch& match) {
    std::vector<AttackTechnique> techniques;
    const std::string* value = metadata(match, "mitre_attack");
    if (value == nullptr) {
        return techniques;
    }
    std::string_view rest = *value;
    while (!rest.empty()) {
        const std::size_t end = rest.find_first_of(", ;");
        const std::string_view token = rest.substr(0, end);
        if (isTechniqueId(token) && techniques.size() < 10) {
            techniques.push_back({.id = std::string(token), .name = {}});
        }
        rest.remove_prefix(end == std::string_view::npos ? rest.size() : end + 1);
    }
    return techniques;
}

} // namespace

Finding findingForYaraMatch(const YaraMatch& match) {
    const std::string* description = metadata(match, "description");
    Finding finding;
    finding.ruleId = "yara." + match.rule;
    finding.title = std::format("YARA rule {} matched", match.rule);
    finding.description = description != nullptr
                              ? *description
                              : std::string("The file meets the conditions of this YARA rule.");
    finding.severity = severityOf(match);
    finding.confidence = Confidence::Medium;
    for (const YaraStringMatch& string : match.strings) {
        if (finding.evidence.size() >= Finding::kMaxEvidence) {
            break;
        }
        finding.evidence.push_back(
            {.description = std::format("{} matched {} bytes", string.identifier, string.length),
             .fileOffset = string.offset,
             .location = std::format("YARA rules '{}'", match.ruleNamespace)});
    }
    if (match.strings.empty()) {
        finding.evidence.push_back({.description = "the rule condition is true for this file",
                                    .fileOffset = std::nullopt,
                                    .location = std::format("YARA rules '{}'", match.ruleNamespace)});
    }
    finding.explanation = "YARA rules describe the byte patterns and properties an analyst looks "
                          "for in a family of files. A match means this file has them.";
    finding.limitations = "A rule is only as precise as its author made it; broad rules also "
                          "match legitimate software. Check the rule before relying on a match.";
    finding.attack = techniquesOf(match);
    finding.nextStep = std::format("Read rule {} in '{}' and compare its strings with the "
                                   "offsets in the evidence.",
                                   match.rule, match.ruleNamespace);
    finding.correlationGroup = "yara";
    return finding;
}

YaraEnrichment::YaraEnrichment(std::shared_ptr<const YaraRuleSet> rules, YaraScanOptions options)
    : rules_(std::move(rules))
    , options_(options) {}

EnrichmentResult YaraEnrichment::run(const EnrichmentInput& input,
                                     const CancellationToken& token) const {
    EnrichmentResult result;
    result.id = std::string(id());
    result.displayName = std::string(displayName());
    result.version = std::string(yaraLibraryVersion());
    result.properties.push_back({.name = "Rules", .value = std::to_string(rules_->ruleCount())});

    const Result<YaraScanResult> scanned =
        scanFileWithYara(*rules_, input.path, token, options_);
    if (!scanned) {
        const ErrorCode code = scanned.error().code;
        result.status = code == ErrorCode::ResourceLimitExceeded || code == ErrorCode::Cancelled
                            ? FieldStatus::incomplete(scanned.error().message)
                            : FieldStatus::parserError(scanned.error().message);
        return result;
    }

    const YaraScanResult& scan = scanned.value();
    result.status =
        scan.matchesTruncated
            ? FieldStatus::incomplete(std::format("only the first {} matching rules are listed",
                                                  YaraScanResult::kMaxMatchingRules))
            : FieldStatus::present();
    result.properties.push_back(
        {.name = "Matching rules", .value = std::to_string(scan.matches.size())});
    for (const YaraMatch& match : scan.matches) {
        result.findings.push_back(findingForYaraMatch(match));
    }
    return result;
}

} // namespace sectoryn
