#include "detectors/ApiCatalogue.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <format>
#include <fstream>
#include <optional>
#include <tuple>
#include <unordered_set>
#include <utility>

namespace sectoryn {

namespace {

using Json = nlohmann::json;

constexpr int kSupportedVersion = 1;
constexpr std::size_t kMaxCategories = 256;
constexpr std::size_t kMaxApisPerCategory = 4096;
constexpr std::size_t kMaxCombinations = 1024;

Error invalid(std::string message) {
    return Error{ErrorCode::InvalidInput, "API catalogue: " + std::move(message)};
}

Result<std::string> stringField(const Json& object, std::string_view key, std::string_view where,
                                bool required = true) {
    const auto it = object.find(key);
    if (it == object.end()) {
        if (required) {
            return invalid(std::format("{} is missing \"{}\"", where, key));
        }
        return std::string{};
    }
    if (!it->is_string()) {
        return invalid(std::format("\"{}\" in {} must be a string", key, where));
    }
    return it->get<std::string>();
}

Result<std::vector<std::string>> stringList(const Json& object, std::string_view key,
                                            std::string_view where, std::size_t maxItems) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_array() || it->empty()) {
        return invalid(std::format("\"{}\" in {} must be a non-empty array", key, where));
    }
    if (it->size() > maxItems) {
        return invalid(std::format("\"{}\" in {} has more than {} entries", key, where, maxItems));
    }
    std::vector<std::string> values;
    values.reserve(it->size());
    for (const Json& item : *it) {
        if (!item.is_string() || item.get_ref<const std::string&>().empty()) {
            return invalid(std::format("\"{}\" in {} must contain non-empty strings", key, where));
        }
        values.push_back(item.get<std::string>());
    }
    return values;
}

template <typename Enum, std::size_t N>
Result<Enum> enumField(const Json& object, std::string_view key, std::string_view where,
                       const std::array<std::pair<std::string_view, Enum>, N>& names) {
    Result<std::string> text = stringField(object, key, where);
    if (!text) {
        return std::move(text).error();
    }
    for (const auto& [name, value] : names) {
        if (text.value() == name) {
            return value;
        }
    }
    return invalid(std::format("\"{}\" in {} has unknown value \"{}\"", key, where, text.value()));
}

constexpr std::array<std::pair<std::string_view, Severity>, 5> kSeverities = {{
    {"informational", Severity::Informational},
    {"low", Severity::Low},
    {"medium", Severity::Medium},
    {"high", Severity::High},
    {"critical", Severity::Critical},
}};

constexpr std::array<std::pair<std::string_view, Confidence>, 3> kConfidences = {{
    {"low", Confidence::Low},
    {"medium", Confidence::Medium},
    {"high", Confidence::High},
}};

Result<ApiCategory> parseCategory(const Json& node, std::size_t index) {
    const std::string where = std::format("category #{}", index);
    if (!node.is_object()) {
        return invalid(where + " must be an object");
    }
    ApiCategory category;
    for (auto [field, key] : {std::pair{&category.id, "id"}, std::pair{&category.name, "name"}}) {
        Result<std::string> value = stringField(node, key, where);
        if (!value) {
            return std::move(value).error();
        }
        *field = std::move(value).value();
    }
    Result<std::vector<std::string>> apis = stringList(node, "apis", where, kMaxApisPerCategory);
    if (!apis) {
        return std::move(apis).error();
    }
    category.apis = std::move(apis).value();
    return category;
}

Result<std::vector<AttackTechnique>> parseAttack(const Json& node, std::string_view where) {
    std::vector<AttackTechnique> techniques;
    const auto it = node.find("attack");
    if (it == node.end()) {
        return techniques;
    }
    if (!it->is_array()) {
        return invalid(std::format("\"attack\" in {} must be an array", where));
    }
    for (const Json& entry : *it) {
        if (!entry.is_object()) {
            return invalid(std::format("\"attack\" entries in {} must be objects", where));
        }
        Result<std::string> id = stringField(entry, "id", where);
        Result<std::string> name = stringField(entry, "name", where);
        if (!id) {
            return std::move(id).error();
        }
        if (!name) {
            return std::move(name).error();
        }
        techniques.push_back({std::move(id).value(), std::move(name).value()});
    }
    return techniques;
}

Result<ApiCombination> parseCombination(const Json& node, std::size_t index) {
    const std::string where = std::format("combination #{}", index);
    if (!node.is_object()) {
        return invalid(where + " must be an object");
    }
    ApiCombination combination;
    const std::array<std::tuple<std::string*, std::string_view, bool>, 6> text = {{
        {&combination.id, "id", true},
        {&combination.title, "title", true},
        {&combination.explanation, "explanation", true},
        {&combination.limitations, "limitations", true},
        {&combination.nextStep, "next_step", true},
        {&combination.group, "group", false},
    }};
    for (const auto& [field, key, required] : text) {
        Result<std::string> value = stringField(node, key, where, required);
        if (!value) {
            return std::move(value).error();
        }
        *field = std::move(value).value();
    }

    Result<std::vector<std::string>> requires_ =
        stringList(node, "requires", where, kMaxCategories);
    Result<Severity> severity = enumField(node, "severity", where, kSeverities);
    Result<Confidence> confidence = enumField(node, "confidence", where, kConfidences);
    Result<std::vector<AttackTechnique>> attack = parseAttack(node, where);
    if (!requires_) {
        return std::move(requires_).error();
    }
    if (!severity) {
        return std::move(severity).error();
    }
    if (!confidence) {
        return std::move(confidence).error();
    }
    if (!attack) {
        return std::move(attack).error();
    }
    combination.requiredCategories = std::move(requires_).value();
    combination.severity = severity.value();
    combination.confidence = confidence.value();
    combination.attack = std::move(attack).value();
    return combination;
}

} // namespace

Result<ApiCatalogue> ApiCatalogue::fromJson(std::string_view json) {
    if (json.size() > kMaxJsonBytes) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("API catalogue exceeds {} bytes", kMaxJsonBytes)};
    }
    const Json root = Json::parse(json, nullptr, /*allow_exceptions=*/false);
    if (root.is_discarded() || !root.is_object()) {
        return invalid("not a valid JSON object");
    }
    const auto version = root.find("version");
    if (version == root.end() || !version->is_number_integer() ||
        version->get<int>() != kSupportedVersion) {
        return invalid(std::format("\"version\" must be {}", kSupportedVersion));
    }

    const auto categories = root.find("categories");
    const auto combinations = root.find("combinations");
    if (categories == root.end() || !categories->is_array() ||
        categories->size() > kMaxCategories) {
        return invalid(std::format("\"categories\" must be an array of at most {} entries",
                                   kMaxCategories));
    }
    if (combinations == root.end() || !combinations->is_array() ||
        combinations->size() > kMaxCombinations) {
        return invalid(std::format("\"combinations\" must be an array of at most {} entries",
                                   kMaxCombinations));
    }

    ApiCatalogue catalogue;
    std::unordered_set<std::string> categoryIds;
    for (std::size_t i = 0; i < categories->size(); ++i) {
        Result<ApiCategory> category = parseCategory((*categories)[i], i);
        if (!category) {
            return std::move(category).error();
        }
        if (!categoryIds.insert(category.value().id).second) {
            return invalid(std::format("duplicate category id \"{}\"", category.value().id));
        }
        for (const std::string& api : category.value().apis) {
            catalogue.index_[api].push_back(catalogue.categories_.size());
        }
        catalogue.categories_.push_back(std::move(category).value());
    }

    std::unordered_set<std::string> combinationIds;
    for (std::size_t i = 0; i < combinations->size(); ++i) {
        Result<ApiCombination> combination = parseCombination((*combinations)[i], i);
        if (!combination) {
            return std::move(combination).error();
        }
        if (!combinationIds.insert(combination.value().id).second) {
            return invalid(std::format("duplicate combination id \"{}\"", combination.value().id));
        }
        for (const std::string& required : combination.value().requiredCategories) {
            if (!categoryIds.contains(required)) {
                return invalid(std::format("combination \"{}\" requires unknown category \"{}\"",
                                           combination.value().id, required));
            }
        }
        catalogue.combinations_.push_back(std::move(combination).value());
    }
    return catalogue;
}

Result<ApiCatalogue> ApiCatalogue::load(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        return Error{ErrorCode::IoFailure, "cannot open API catalogue"};
    }
    std::string text(kMaxJsonBytes + 1, '\0');
    in.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (in.bad()) {
        return Error{ErrorCode::IoFailure, "cannot read API catalogue"};
    }
    text.resize(static_cast<std::size_t>(in.gcount()));
    return fromJson(text);
}

Result<ApiCatalogue> ApiCatalogue::builtIn() {
    return fromJson(builtInApiCatalogueJson());
}

const std::vector<std::size_t>& ApiCatalogue::categoriesOf(std::string_view function) const {
    static const std::vector<std::size_t> kNone;
    const auto it = index_.find(std::string(function));
    return it == index_.end() ? kNone : it->second;
}

} // namespace sectoryn
