#include "detectors/yara/YaraCompiler.hpp"

#include "detectors/yara/YaraApi.hpp"
#include "utilities/FileIo.hpp"

#include <format>
#include <utility>

namespace sectoryn {

namespace {

struct CompilerDeleter {
    void operator()(YR_COMPILER* compiler) const noexcept { yr_compiler_destroy(compiler); }
};

struct CallbackState {
    const std::string* source = nullptr;
    std::vector<YaraDiagnostic>* diagnostics = nullptr;
};

// Called from C code, so it must not let an exception escape.
void collectDiagnostic(int errorLevel, const char* /*fileName*/, int line,
                       const YR_RULE* /*rule*/, const char* message, void* userData) noexcept {
    auto& state = *static_cast<CallbackState*>(userData);
    if (state.diagnostics->size() >= YaraLimits::kMaxDiagnostics) {
        return;
    }
    try {
        state.diagnostics->push_back({.source = *state.source,
                                      .line = line,
                                      .message = message != nullptr ? message : "",
                                      .warning = errorLevel == YARA_ERROR_LEVEL_WARNING});
    } catch (...) { // NOLINT(bugprone-empty-catch): must not throw into libyara
        // Out of memory while recording a diagnostic; the compile status still reports failure.
    }
}

Status checkLimits(std::span<const YaraSource> sources) {
    if (sources.size() > YaraLimits::kMaxSources) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("at most {} rule files can be used", YaraLimits::kMaxSources)};
    }
    std::size_t total = 0;
    for (const YaraSource& source : sources) {
        if (source.text.size() > YaraLimits::kMaxSourceBytes) {
            return Error{ErrorCode::ResourceLimitExceeded,
                         std::format("rule file '{}' is larger than {} bytes", source.name,
                                     YaraLimits::kMaxSourceBytes)};
        }
        total += source.text.size();
    }
    if (total > YaraLimits::kMaxTotalBytes) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("rule files exceed {} bytes in total", YaraLimits::kMaxTotalBytes)};
    }
    return {};
}

} // namespace

YaraRuleSet::YaraRuleSet(std::shared_ptr<YaraRuntime> runtime, YR_RULES* rules) noexcept
    : runtime_(std::move(runtime))
    , rules_(rules) {}

YaraRuleSet::~YaraRuleSet() {
    yr_rules_destroy(rules_);
}

std::size_t YaraRuleSet::ruleCount() const noexcept {
    return rules_->num_rules;
}

Result<YaraCompilation> compileYaraRules(std::span<const YaraSource> sources) {
    if (Status status = checkLimits(sources); !status) {
        return std::move(status).error();
    }
    Result<std::shared_ptr<YaraRuntime>> runtime = YaraRuntime::acquire();
    if (!runtime) {
        return std::move(runtime).error();
    }

    YR_COMPILER* rawCompiler = nullptr;
    if (yr_compiler_create(&rawCompiler) != ERROR_SUCCESS) {
        return Error{ErrorCode::ResourceLimitExceeded, "cannot create a YARA compiler"};
    }
    const std::unique_ptr<YR_COMPILER, CompilerDeleter> compiler(rawCompiler);
    // Without an include callback libyara rejects `include`, so rules cannot read other files.
    yr_compiler_set_include_callback(compiler.get(), nullptr, nullptr, nullptr);

    YaraCompilation compilation;
    CallbackState state{.diagnostics = &compilation.diagnostics};
    yr_compiler_set_callback(compiler.get(), collectDiagnostic, &state);

    for (const YaraSource& source : sources) {
        state.source = &source.name;
        const char* ruleNamespace = source.name.empty() ? "default" : source.name.c_str();
        // After a failed source libyara refuses further input, so compilation stops here.
        if (yr_compiler_add_bytes(compiler.get(), source.text.data(), source.text.size(),
                                  ruleNamespace) != 0) {
            return compilation;
        }
    }

    YR_RULES* rules = nullptr;
    if (const int status = yr_compiler_get_rules(compiler.get(), &rules); status != ERROR_SUCCESS) {
        return Error{status == ERROR_INSUFFICIENT_MEMORY ? ErrorCode::ResourceLimitExceeded
                                                         : ErrorCode::Internal,
                     std::format("cannot finish compiling YARA rules (error {})", status)};
    }
    compilation.rules = std::make_shared<const YaraRuleSet>(std::move(runtime).value(), rules);
    return compilation;
}

Result<YaraCompilation> compileYaraRuleFiles(std::span<const std::filesystem::path> files) {
    if (files.size() > YaraLimits::kMaxSources) {
        return Error{ErrorCode::ResourceLimitExceeded,
                     std::format("at most {} rule files can be used", YaraLimits::kMaxSources)};
    }
    std::vector<YaraSource> sources;
    sources.reserve(files.size());
    for (const std::filesystem::path& file : files) {
        const std::u8string name = file.filename().u8string();
        Result<std::string> text = readSmallFile(file, YaraLimits::kMaxSourceBytes);
        if (!text) {
            return Error{text.error().code,
                         std::format("{}: {}", std::string(name.begin(), name.end()),
                                     text.error().message)};
        }
        sources.push_back({.name = std::string(name.begin(), name.end()),
                           .text = std::move(text).value()});
    }
    return compileYaraRules(sources);
}

} // namespace sectoryn
