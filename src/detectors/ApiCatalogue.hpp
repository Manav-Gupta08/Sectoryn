#pragma once

#include "core/Result.hpp"
#include "detectors/Finding.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace sectoryn {

struct ApiCategory {
    std::string id;
    std::string name;
    std::vector<std::string> apis;
};

// A capability inferred when every listed category is imported at least once.
struct ApiCombination {
    std::string id;
    std::string title;
    std::vector<std::string> requiredCategories;
    Severity severity = Severity::Low;
    Confidence confidence = Confidence::Low;
    std::vector<AttackTechnique> attack;
    std::string explanation;
    std::string limitations;
    std::string nextStep;
    std::string group;
};

// Suspicious-API knowledge, kept in JSON so it can be reviewed and extended without
// recompiling. See resources/rules/api_indicators.json for the format.
class ApiCatalogue {
public:
    static constexpr std::size_t kMaxJsonBytes = 1024 * 1024;

    [[nodiscard]] static Result<ApiCatalogue> fromJson(std::string_view json);
    [[nodiscard]] static Result<ApiCatalogue> load(const std::filesystem::path& path);
    // The catalogue shipped with Sectoryn.
    [[nodiscard]] static Result<ApiCatalogue> builtIn();

    [[nodiscard]] const std::vector<ApiCategory>& categories() const noexcept {
        return categories_;
    }
    [[nodiscard]] const std::vector<ApiCombination>& combinations() const noexcept {
        return combinations_;
    }

    // Indexes into categories() of every category listing `function`. Matching is exact,
    // as PE import names are case-sensitive.
    [[nodiscard]] const std::vector<std::size_t>& categoriesOf(std::string_view function) const;

private:
    std::vector<ApiCategory> categories_;
    std::vector<ApiCombination> combinations_;
    std::unordered_map<std::string, std::vector<std::size_t>> index_;
};

// Contents of resources/rules/api_indicators.json, compiled in by the build.
[[nodiscard]] std::string_view builtInApiCatalogueJson() noexcept;

} // namespace sectoryn
