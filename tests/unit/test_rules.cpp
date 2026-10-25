#include "detectors/ApiCatalogue.hpp"
#include "detectors/DefaultRules.hpp"
#include "detectors/RuleRegistry.hpp"
#include "detectors/rules/ApiCombinationRule.hpp"
#include "detectors/rules/EntropyRule.hpp"
#include "detectors/rules/HeaderAnomalyRule.hpp"
#include "detectors/rules/SectionAnomalyRule.hpp"
#include "detectors/rules/SectionPermissionRule.hpp"
#include "detectors/rules/StringIndicatorRule.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <format>
#include <stdexcept>
#include <string>
#include <vector>

namespace sectoryn {
namespace {

Section makeSection(std::string name, std::uint32_t va, std::uint32_t raw,
                    std::uint32_t characteristics) {
    Section section;
    std::copy_n(name.begin(), std::min<std::size_t>(name.size(), 8), section.rawName.begin());
    section.name = std::move(name);
    section.virtualAddress = va;
    section.virtualSize = 0x1000;
    section.pointerToRawData = raw;
    section.sizeOfRawData = 0x1000;
    section.characteristics = characteristics;
    return section;
}

// A small, consistent image that individual tests modify.
struct Fixture {
    PeImage image;
    SectionAnalysis sections;
    EntropyReport entropy;
    StringExtraction strings;
    std::vector<Indicator> indicators;

    Fixture() {
        image.fileSize = 0x10000;
        image.optional.sectionAlignment = 0x1000;
        image.optional.fileAlignment = 0x200;
        image.optional.sizeOfHeaders = 0x400;
        image.optional.sizeOfImage = 0x10000;
        image.sectionTable = FieldStatus::present();
        image.imports.status = FieldStatus::absent("empty");
        image.imports.delayStatus = FieldStatus::absent("empty");
        image.sections = {makeSection(".text", 0x1000, 0x400, 0x60000020),
                          makeSection(".data", 0x2000, 0x1400, 0xC0000040)};
        reanalyze();
    }

    void reanalyze() {
        sections = analyzeSections(image);
        entropy.sections.assign(image.sections.size(), RangeEntropy{5.0, 0x1000});
    }

    [[nodiscard]] RuleContext context() const {
        return {image, sections, &entropy, &strings, &indicators};
    }

    std::vector<Finding> run(const IRule& rule) const {
        std::vector<Finding> findings;
        const RuleOutcome outcome = rule.evaluate(context(), findings);
        EXPECT_TRUE(outcome.evaluated) << outcome.skipReason;
        return findings;
    }
};

std::vector<std::string> ids(const std::vector<Finding>& findings) {
    std::vector<std::string> out;
    for (const Finding& finding : findings) {
        out.push_back(finding.ruleId);
    }
    return out;
}

void expectExplained(const Finding& finding) {
    EXPECT_FALSE(finding.title.empty()) << finding.ruleId;
    EXPECT_FALSE(finding.description.empty()) << finding.ruleId;
    EXPECT_FALSE(finding.explanation.empty()) << finding.ruleId;
    EXPECT_FALSE(finding.limitations.empty()) << finding.ruleId;
    EXPECT_FALSE(finding.nextStep.empty()) << finding.ruleId;
    EXPECT_FALSE(finding.evidence.empty()) << finding.ruleId;
    EXPECT_LE(finding.evidence.size(), Finding::kMaxEvidence) << finding.ruleId;
}

class StubRule final : public IRule {
public:
    enum class Mode { Find, Skip, Throw };

    StubRule(std::string id, Mode mode)
        : id_(std::move(id))
        , mode_(mode) {}

    [[nodiscard]] std::string_view id() const noexcept override { return id_; }
    [[nodiscard]] std::string_view summary() const noexcept override { return "stub"; }

    [[nodiscard]] RuleOutcome evaluate(const RuleContext&,
                                       std::vector<Finding>& findings) const override {
        findings.push_back({.ruleId = id_ + ".finding", .title = "stub"});
        if (mode_ == Mode::Throw) {
            throw std::runtime_error("broken rule");
        }
        return mode_ == Mode::Skip ? RuleOutcome::skipped("no input") : RuleOutcome::ran();
    }

private:
    std::string id_;
    Mode mode_;
};

TEST(RuleRegistry, RejectsInvalidRegistrations) {
    RuleRegistry registry;
    EXPECT_FALSE(registry.add(nullptr).hasValue());
    EXPECT_TRUE(registry.add(std::make_unique<StubRule>("a", StubRule::Mode::Find)).hasValue());
    EXPECT_FALSE(registry.add(std::make_unique<StubRule>("a", StubRule::Mode::Find)).hasValue());
    EXPECT_FALSE(registry.add(std::make_unique<StubRule>("", StubRule::Mode::Find)).hasValue());
    EXPECT_EQ(registry.size(), 1U);
}

TEST(RuleRegistry, IsolatesFailingAndSkippedRules) {
    RuleRegistry registry;
    ASSERT_TRUE(registry.add(std::make_unique<StubRule>("first", StubRule::Mode::Find)).hasValue());
    ASSERT_TRUE(
        registry.add(std::make_unique<StubRule>("broken", StubRule::Mode::Throw)).hasValue());
    ASSERT_TRUE(registry.add(std::make_unique<StubRule>("skips", StubRule::Mode::Skip)).hasValue());
    ASSERT_TRUE(registry.add(std::make_unique<StubRule>("last", StubRule::Mode::Find)).hasValue());

    const Fixture fixture;
    const Result<RuleEvaluation> evaluation = registry.evaluate(fixture.context(), {});
    ASSERT_TRUE(evaluation.hasValue());
    EXPECT_EQ(ids(evaluation.value().findings),
              (std::vector<std::string>{"first.finding", "skips.finding", "last.finding"}));
    ASSERT_EQ(evaluation.value().failed.size(), 1U);
    EXPECT_EQ(evaluation.value().failed[0].ruleId, "broken");
    EXPECT_EQ(evaluation.value().failed[0].reason, "broken rule");
    ASSERT_EQ(evaluation.value().skipped.size(), 1U);
    EXPECT_EQ(evaluation.value().skipped[0].reason, "no input");
}

TEST(RuleRegistry, StopsWhenCancelled) {
    RuleRegistry registry;
    ASSERT_TRUE(registry.add(std::make_unique<StubRule>("a", StubRule::Mode::Find)).hasValue());
    CancellationSource source;
    source.request_stop();
    const Fixture fixture;
    const Result<RuleEvaluation> evaluation =
        registry.evaluate(fixture.context(), source.get_token());
    ASSERT_FALSE(evaluation.hasValue());
    EXPECT_EQ(evaluation.error().code, ErrorCode::Cancelled);
}

TEST(SectionPermissionRule, CleanImageHasNoFindings) {
    const Fixture fixture;
    EXPECT_TRUE(fixture.run(rules::SectionPermissionRule{}).empty());
}

TEST(SectionPermissionRule, FlagsWritableExecutableSection) {
    Fixture fixture;
    fixture.image.sections[1].characteristics = 0xE0000020;
    fixture.reanalyze();
    const std::vector<Finding> findings = fixture.run(rules::SectionPermissionRule{});
    ASSERT_EQ(ids(findings), (std::vector<std::string>{"section.writable_executable"}));
    expectExplained(findings[0]);
    EXPECT_EQ(findings[0].severity, Severity::Medium);
    EXPECT_EQ(findings[0].evidence[0].location, "section 1 '.data'");
    EXPECT_EQ(findings[0].evidence[0].fileOffset, 0x1400U);
    EXPECT_EQ(findings[0].correlationGroup, "packing");
}

TEST(SectionPermissionRule, SkipsWithoutSectionTable) {
    Fixture fixture;
    fixture.image.sectionTable = FieldStatus::invalid("truncated");
    std::vector<Finding> findings;
    const RuleOutcome outcome =
        rules::SectionPermissionRule{}.evaluate(fixture.context(), findings);
    EXPECT_FALSE(outcome.evaluated);
    EXPECT_FALSE(outcome.skipReason.empty());
}

TEST(SectionAnomalyRule, FlagsPackerNamesAndOverlaps) {
    Fixture fixture;
    fixture.image.sections = {makeSection("UPX0", 0x1000, 0x400, 0x60000020),
                              makeSection("UPX1", 0x1800, 0x400, 0x60000020)};
    fixture.reanalyze();
    const std::vector<Finding> findings = fixture.run(rules::SectionAnomalyRule{});
    EXPECT_EQ(ids(findings), (std::vector<std::string>{"section.packer_name", "section.overlap",
                                                       "section.layout_inconsistent"}));
    for (const Finding& finding : findings) {
        expectExplained(finding);
    }
    EXPECT_EQ(findings[0].evidence.size(), 2U);
}

TEST(SectionAnomalyRule, CapsEvidence) {
    Fixture fixture;
    fixture.image.fileSize = 0x100000;
    fixture.image.optional.sizeOfImage = 0x100000;
    fixture.image.sections.clear();
    for (std::uint32_t i = 0; i < 40; ++i) {
        fixture.image.sections.push_back(
            makeSection("", 0x1000 * (i + 1), 0x400 + 0x1000 * i, 0x40000040));
    }
    fixture.reanalyze();
    const std::vector<Finding> findings = fixture.run(rules::SectionAnomalyRule{});
    ASSERT_EQ(ids(findings), (std::vector<std::string>{"section.unusual_name"}));
    EXPECT_EQ(findings[0].evidence.size(), Finding::kMaxEvidence);
    EXPECT_NE(findings[0].description.find("40 occurrences"), std::string::npos);
}

TEST(HeaderAnomalyRule, SeparatesEntryPointIssues) {
    Fixture fixture;
    fixture.image.issues = {{"header.entry_point_in_headers", "entry in headers"},
                            {"header.file_alignment", "bad alignment"},
                            {"header.size_of_image", "too small"}};
    const std::vector<Finding> findings = fixture.run(rules::HeaderAnomalyRule{});
    ASSERT_EQ(ids(findings),
              (std::vector<std::string>{"header.entry_point_unusual", "header.inconsistent"}));
    EXPECT_EQ(findings[0].evidence.size(), 1U);
    EXPECT_EQ(findings[1].evidence.size(), 2U);
    expectExplained(findings[1]);
}

TEST(EntropyRule, DistinguishesCodeAndData) {
    Fixture fixture;
    fixture.entropy.sections = {RangeEntropy{7.9, 0x1000}, RangeEntropy{7.5, 0x1000}};
    const std::vector<Finding> findings = fixture.run(rules::EntropyRule{});
    ASSERT_EQ(ids(findings),
              (std::vector<std::string>{"entropy.packed_code", "entropy.high_section"}));
    EXPECT_EQ(findings[0].severity, Severity::Medium);
    expectExplained(findings[0]);
}

TEST(EntropyRule, IgnoresSmallOrUnmeasuredRanges) {
    Fixture fixture;
    fixture.entropy.sections = {RangeEntropy{7.9, rules::EntropyRule::kMinBytes - 1},
                                RangeEntropy{std::nullopt, 0x1000}};
    EXPECT_TRUE(fixture.run(rules::EntropyRule{}).empty());
}

TEST(EntropyRule, FlagsOverlayButNotSignatureOnly) {
    Fixture fixture;
    fixture.image.overlay = {FieldStatus::present(), 0x8000, 0x4000, false};
    fixture.entropy.overlay = {7.95, 0x4000};
    EXPECT_EQ(ids(fixture.run(rules::EntropyRule{})),
              (std::vector<std::string>{"entropy.high_overlay"}));

    fixture.image.overlay.containsCertificateTable = true;
    fixture.image.certificate = {FieldStatus::present(), 0x8000, 0x4000};
    EXPECT_TRUE(fixture.run(rules::EntropyRule{}).empty());
}

TEST(EntropyRule, SkipsWithoutEntropy) {
    const Fixture fixture;
    RuleContext context = fixture.context();
    context.entropy = nullptr;
    std::vector<Finding> findings;
    EXPECT_FALSE(rules::EntropyRule{}.evaluate(context, findings).evaluated);
}

TEST(ApiCatalogue, BuiltInCatalogueIsValid) {
    const Result<ApiCatalogue> catalogue = ApiCatalogue::builtIn();
    ASSERT_TRUE(catalogue.hasValue()) << catalogue.error().describe();
    EXPECT_GE(catalogue.value().categories().size(), 10U);
    EXPECT_GE(catalogue.value().combinations().size(), 5U);
    EXPECT_FALSE(catalogue.value().categoriesOf("WriteProcessMemory").empty());
    EXPECT_TRUE(catalogue.value().categoriesOf("writeprocessmemory").empty());
    EXPECT_TRUE(catalogue.value().categoriesOf("printf").empty());
}

TEST(ApiCatalogue, RejectsInvalidDocuments) {
    const std::string category = R"({"id": "c", "name": "C", "apis": ["F"]})";
    const auto document = [&](const std::string& combinations, int version = 1) {
        return std::format(R"({{"version": {}, "categories": [{}], "combinations": [{}]}})",
                           version, category, combinations);
    };
    const std::string combination =
        R"({"id": "x", "title": "X", "requires": ["c"], "severity": "low", "confidence": "low",
            "explanation": "e", "limitations": "l", "next_step": "n"})";

    EXPECT_TRUE(ApiCatalogue::fromJson(document(combination)).hasValue());
    EXPECT_FALSE(ApiCatalogue::fromJson("{not json").hasValue());
    EXPECT_FALSE(ApiCatalogue::fromJson(document(combination, 2)).hasValue());
    EXPECT_FALSE(ApiCatalogue::fromJson(document(combination + "," + combination)).hasValue());

    std::string unknown = combination;
    unknown.replace(unknown.find(R"(["c"])"), 5, R"(["z"])");
    EXPECT_FALSE(ApiCatalogue::fromJson(document(unknown)).hasValue());

    std::string badSeverity = combination;
    badSeverity.replace(badSeverity.find(R"("low")"), 5, R"("bad")");
    EXPECT_FALSE(ApiCatalogue::fromJson(document(badSeverity)).hasValue());
}

ImportedModule importedModule(std::string name, std::vector<std::string> functions) {
    ImportedModule imported;
    imported.name = std::move(name);
    for (std::string& function : functions) {
        imported.functions.push_back({std::move(function), std::nullopt, 0});
    }
    return imported;
}

TEST(ApiCombinationRule, ReportsCompleteCombinationsOnly) {
    Result<ApiCatalogue> catalogue = ApiCatalogue::builtIn();
    ASSERT_TRUE(catalogue.hasValue());
    const rules::ApiCombinationRule rule(std::move(catalogue).value());

    Fixture fixture;
    fixture.image.imports.status = FieldStatus::present();
    fixture.image.imports.modules = {
        importedModule("KERNEL32.dll", {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory"})};
    EXPECT_TRUE(fixture.run(rule).empty());

    fixture.image.imports.modules[0].functions.push_back({"CreateRemoteThread", std::nullopt, 0});
    const std::vector<Finding> findings = fixture.run(rule);
    ASSERT_EQ(ids(findings), (std::vector<std::string>{"api.process_injection"}));
    expectExplained(findings[0]);
    EXPECT_EQ(findings[0].severity, Severity::High);
    EXPECT_EQ(findings[0].evidence.size(), 4U);
    EXPECT_EQ(findings[0].evidence[0].description,
              "KERNEL32.dll!OpenProcess (Opening other processes)");
    ASSERT_FALSE(findings[0].attack.empty());
    EXPECT_EQ(findings[0].attack[0].id, "T1055");
}

TEST(ApiCombinationRule, SkipsUnreadableImportsAndNotesPartialOnes) {
    Result<ApiCatalogue> catalogue = ApiCatalogue::builtIn();
    ASSERT_TRUE(catalogue.hasValue());
    const rules::ApiCombinationRule rule(std::move(catalogue).value());

    Fixture fixture;
    fixture.image.imports.status = FieldStatus::parserError("unreadable");
    fixture.image.imports.delayStatus = FieldStatus::parserError("unreadable");
    std::vector<Finding> findings;
    EXPECT_FALSE(rule.evaluate(fixture.context(), findings).evaluated);

    fixture.image.imports.status = FieldStatus::incomplete("limit");
    fixture.image.imports.delayStatus = FieldStatus::absent("empty");
    fixture.image.imports.modules = {importedModule("ADVAPI32.dll", {"CreateServiceW"})};
    findings = fixture.run(rule);
    ASSERT_EQ(ids(findings), (std::vector<std::string>{"api.service_installation"}));
    EXPECT_NE(findings[0].limitations.find("only partly read"), std::string::npos);
}

TEST(StringIndicatorRule, GroupsIndicatorsByKind) {
    Fixture fixture;
    fixture.indicators = {
        {IndicatorKind::PowerShell, "powershell", 0, 0x100},
        {IndicatorKind::Url, "http://example.com/a", 1, 0x200},
        {IndicatorKind::IpV4Address, "10.0.0.1", 2, 0x300},
        {IndicatorKind::Persistence, "CurrentVersion\\Run", 3, 0x400},
    };
    const std::vector<Finding> findings = fixture.run(rules::StringIndicatorRule{});
    EXPECT_EQ(ids(findings), (std::vector<std::string>{"strings.powershell", "strings.persistence",
                                                       "strings.network"}));
    EXPECT_EQ(findings[2].evidence.size(), 2U);
    EXPECT_EQ(findings[0].evidence[0].fileOffset, 0x100U);
    for (const Finding& finding : findings) {
        expectExplained(finding);
    }
}

TEST(StringIndicatorRule, NotesExtractionLimit) {
    Fixture fixture;
    fixture.strings.limitReached = true;
    fixture.indicators = {{IndicatorKind::EncodedData, "QUJD", 0, 0}};
    const std::vector<Finding> findings = fixture.run(rules::StringIndicatorRule{});
    ASSERT_EQ(findings.size(), 1U);
    EXPECT_NE(findings[0].limitations.find("configured limit"), std::string::npos);
}

TEST(StringIndicatorRule, SkipsWithoutStrings) {
    const Fixture fixture;
    RuleContext context = fixture.context();
    context.strings = nullptr;
    std::vector<Finding> findings;
    EXPECT_FALSE(rules::StringIndicatorRule{}.evaluate(context, findings).evaluated);
}

TEST(DefaultRules, AreRegisteredAndDeterministic) {
    Result<ApiCatalogue> catalogue = ApiCatalogue::builtIn();
    ASSERT_TRUE(catalogue.hasValue());
    Result<RuleRegistry> registry = createDefaultRules(std::move(catalogue).value());
    ASSERT_TRUE(registry.hasValue()) << registry.error().describe();
    EXPECT_EQ(registry.value().size(), 7U);

    Fixture fixture;
    fixture.image.sections[1].characteristics = 0xE0000020;
    fixture.image.sections[0].name = "UPX0";
    fixture.reanalyze();
    fixture.entropy.sections = {RangeEntropy{7.9, 0x1000}, RangeEntropy{7.9, 0x1000}};

    const Result<RuleEvaluation> first = registry.value().evaluate(fixture.context(), {});
    const Result<RuleEvaluation> second = registry.value().evaluate(fixture.context(), {});
    ASSERT_TRUE(first.hasValue());
    ASSERT_TRUE(second.hasValue());
    EXPECT_FALSE(first.value().findings.empty());
    EXPECT_EQ(ids(first.value().findings), ids(second.value().findings));
}

} // namespace
} // namespace sectoryn
