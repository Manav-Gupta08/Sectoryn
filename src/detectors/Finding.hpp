#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {

// How much a finding matters if it is real. Kept separate from Confidence, which says how sure
// the rule is that the finding applies at all.
enum class Severity : std::uint8_t { Informational, Low, Medium, High, Critical };

enum class Confidence : std::uint8_t { Low, Medium, High };

[[nodiscard]] std::string_view toString(Severity severity) noexcept;
[[nodiscard]] std::string_view toString(Confidence confidence) noexcept;

struct Evidence {
    // What was observed, e.g. "section '.text' is RWX" or "imports KERNEL32.dll!VirtualAllocEx".
    std::string description;
    // Where it was observed, when that can be pinned down.
    std::optional<std::uint64_t> fileOffset;
    // Structure the evidence comes from, e.g. "section .text" or "import table".
    std::string location;
};

struct AttackTechnique {
    std::string id;
    std::string name;
};

struct Finding {
    // Rules list at most this many evidence items per finding; the description gives the total.
    static constexpr std::size_t kMaxEvidence = 25;

    // Stable identifier such as "section.writable_executable". Never reused for another meaning.
    std::string ruleId{};
    std::string title{};
    std::string description{};
    Severity severity = Severity::Informational;
    Confidence confidence = Confidence::Low;
    std::vector<Evidence> evidence{};
    // Why the observation can matter during triage.
    std::string explanation{};
    // Benign reasons for the same observation and what the rule cannot see.
    std::string limitations{};
    std::vector<AttackTechnique> attack{};
    std::string nextStep{};
    // Findings that describe the same underlying behavior share a group and are scored once.
    std::string correlationGroup{};
};

} // namespace sectoryn
