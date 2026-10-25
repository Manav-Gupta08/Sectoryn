#pragma once

#include "core/CancellationToken.hpp"
#include "detectors/Finding.hpp"
#include "parsers/FieldStatus.hpp"
#include "parsers/PeModel.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn {

class FileReader;

struct EnrichmentInput {
    const std::filesystem::path& path;
    const std::string& sha256;
    const PeImage& image;
    // Shared with the engine and not thread-safe; read only during run().
    FileReader& reader;
};

struct EnrichmentProperty {
    std::string name;
    std::string value;
};

struct EnrichmentResult {
    std::string id;
    std::string displayName;
    // Version of the module or library that produced the result, for reports.
    std::string version;
    FieldStatus status;
    std::vector<EnrichmentProperty> properties;
    std::vector<Finding> findings;
    // Set when the module contacted a remote service; reports state this explicitly.
    bool usedNetwork = false;
};

// An optional analysis step that runs after the built-in static analysis, such as signature
// verification, YARA scanning or a reputation lookup. Implementations live in their own
// modules, so the engine has no compile-time dependency on them.
class IEnrichment {
public:
    virtual ~IEnrichment() = default;

    [[nodiscard]] virtual std::string_view id() const noexcept = 0;
    [[nodiscard]] virtual std::string_view displayName() const noexcept = 0;

    // Must not throw for problems with the file or an external service; those belong in the
    // returned status. Must be safe to call from several threads at once.
    [[nodiscard]] virtual EnrichmentResult run(const EnrichmentInput& input,
                                               const CancellationToken& token) const = 0;

protected:
    IEnrichment() = default;
    IEnrichment(const IEnrichment&) = default;
    IEnrichment& operator=(const IEnrichment&) = default;
    IEnrichment(IEnrichment&&) = default;
    IEnrichment& operator=(IEnrichment&&) = default;
};

} // namespace sectoryn
