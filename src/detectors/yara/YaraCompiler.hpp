#pragma once

#include "core/Result.hpp"
#include "detectors/yara/YaraRuntime.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

struct YR_RULES;

namespace sectoryn {

struct YaraSource {
    // Shown in diagnostics and used as the rule namespace, so equal rule names in different
    // sources do not clash.
    std::string name{};
    std::string text{};
};

struct YaraDiagnostic {
    std::string source{};
    int line = 0;
    std::string message{};
    bool warning = false;
};

// Compiled rules. Immutable, and safe to scan with from several threads at once.
class YaraRuleSet {
public:
    // Takes ownership of `rules`.
    YaraRuleSet(std::shared_ptr<YaraRuntime> runtime, YR_RULES* rules) noexcept;
    ~YaraRuleSet();

    YaraRuleSet(const YaraRuleSet&) = delete;
    YaraRuleSet& operator=(const YaraRuleSet&) = delete;
    YaraRuleSet(YaraRuleSet&&) = delete;
    YaraRuleSet& operator=(YaraRuleSet&&) = delete;

    [[nodiscard]] std::size_t ruleCount() const noexcept;
    [[nodiscard]] YR_RULES* native() const noexcept { return rules_; }

private:
    std::shared_ptr<YaraRuntime> runtime_;
    YR_RULES* rules_;
};

struct YaraCompilation {
    // Null when any source had an error.
    std::shared_ptr<const YaraRuleSet> rules{};
    std::vector<YaraDiagnostic> diagnostics{};
};

struct YaraLimits {
    static constexpr std::size_t kMaxSources = 1024;
    static constexpr std::size_t kMaxSourceBytes = 16 * 1024 * 1024;
    static constexpr std::size_t kMaxTotalBytes = 64 * 1024 * 1024;
    static constexpr std::size_t kMaxDiagnostics = 100;
};

// Compiles rule text. `include` directives are refused, so rules cannot pull in other files.
// Mistakes in the rules are reported as diagnostics with null rules; the returned error is kept
// for problems outside the rules, such as exceeding YaraLimits or libyara failing to start.
[[nodiscard]] Result<YaraCompilation> compileYaraRules(std::span<const YaraSource> sources);

// Reads each file, with the limits of YaraLimits, and compiles them together.
[[nodiscard]] Result<YaraCompilation>
compileYaraRuleFiles(std::span<const std::filesystem::path> files);

} // namespace sectoryn
