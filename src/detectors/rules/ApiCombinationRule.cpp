#include "detectors/rules/ApiCombinationRule.hpp"

#include "detectors/rules/RuleSupport.hpp"

#include <algorithm>
#include <format>
#include <utility>

namespace sectoryn::rules {

namespace {

constexpr std::string_view kVisibilityNote =
    " Only the import tables are checked: functions resolved at run time or imported by ordinal "
    "are not visible to this rule.";

struct ImportRef {
    const ImportedModule* module;
    const ImportedFunction* function;
};

bool unreadable(const FieldStatus& status) {
    return !status.hasData() && status.state != FieldState::Absent;
}

} // namespace

ApiCombinationRule::ApiCombinationRule(ApiCatalogue catalogue)
    : catalogue_(std::move(catalogue)) {}

RuleOutcome ApiCombinationRule::evaluate(const RuleContext& context,
                                         std::vector<Finding>& findings) const {
    const ImportTable& imports = context.image.imports;
    if (unreadable(imports.status) && unreadable(imports.delayStatus)) {
        return RuleOutcome::skipped("the import tables could not be read: " +
                                    imports.status.detail);
    }

    std::vector<std::vector<ImportRef>> matches(catalogue_.categories().size());
    for (const ImportedModule& imported : imports.modules) {
        for (const ImportedFunction& function : imported.functions) {
            if (function.name.empty()) {
                continue;
            }
            for (const std::size_t category : catalogue_.categoriesOf(function.name)) {
                matches[category].push_back({&imported, &function});
            }
        }
    }

    const auto categoryIndex = [this](const std::string& id) {
        const auto& categories = catalogue_.categories();
        return static_cast<std::size_t>(
            std::ranges::find(categories, id, &ApiCategory::id) - categories.begin());
    };
    const bool partial = imports.status.state == FieldState::Incomplete ||
                         imports.delayStatus.state == FieldState::Incomplete ||
                         unreadable(imports.status) || unreadable(imports.delayStatus);

    for (const ApiCombination& combination : catalogue_.combinations()) {
        const bool satisfied = std::ranges::all_of(
            combination.requiredCategories,
            [&](const std::string& id) { return !matches[categoryIndex(id)].empty(); });
        if (!satisfied) {
            continue;
        }

        Finding finding{
            .ruleId = combination.id,
            .title = combination.title,
            .description = "The file imports functions from each of these groups:",
            .severity = combination.severity,
            .confidence = combination.confidence,
            .explanation = combination.explanation,
            .limitations = combination.limitations + std::string(kVisibilityNote),
            .attack = combination.attack,
            .nextStep = combination.nextStep,
            .correlationGroup = combination.group,
        };
        for (std::size_t i = 0; i < combination.requiredCategories.size(); ++i) {
            const std::size_t category = categoryIndex(combination.requiredCategories[i]);
            finding.description += std::format("{} {}", i == 0 ? "" : ",",
                                               catalogue_.categories()[category].name);
            for (const ImportRef& ref : matches[category]) {
                addEvidence(finding,
                            {.description = std::format("{}!{} ({})", ref.module->name,
                                                        ref.function->name,
                                                        catalogue_.categories()[category].name),
                             .fileOffset = std::nullopt,
                             .location = ref.module->delayLoaded ? "delay import table"
                                                                 : "import table"});
            }
        }
        finding.description += '.';
        if (partial) {
            finding.limitations += " The import tables were only partly read.";
        }
        findings.push_back(std::move(finding));
    }
    return RuleOutcome::ran();
}

} // namespace sectoryn::rules
