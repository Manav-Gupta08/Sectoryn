#include "parsers/LiefDetail.hpp"
#include "parsers/PeConstants.hpp"

#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/DelayImport.hpp>
#include <LIEF/PE/DelayImportEntry.hpp>
#include <LIEF/PE/Import.hpp>
#include <LIEF/PE/ImportEntry.hpp>

#include <format>
#include <optional>

namespace sectoryn::lief_detail {

namespace {

struct ImportBudget {
    std::size_t modulesLeft;
    std::size_t functionsLeft;
    bool truncated = false;
};

// Works for both regular and delay-load descriptors, which LIEF models as separate types.
template <typename Descriptor>
void appendModule(const Descriptor& source, bool delayLoaded, ImportBudget& budget,
                  std::vector<ImportedModule>& modules) {
    if (budget.modulesLeft == 0) {
        budget.truncated = true;
        return;
    }
    --budget.modulesLeft;

    ImportedModule imported;
    imported.name = pe::escapeNonPrintable(source.name());
    imported.delayLoaded = delayLoaded;
    for (const auto& entry : source.entries()) {
        if (budget.functionsLeft == 0) {
            budget.truncated = true;
            break;
        }
        --budget.functionsLeft;

        ImportedFunction function;
        if (entry.is_ordinal()) {
            function.ordinal = entry.ordinal();
        } else {
            function.name = pe::escapeNonPrintable(entry.name());
            function.hint = entry.hint();
        }
        imported.functions.push_back(std::move(function));
    }
    modules.push_back(std::move(imported));
}

} // namespace

void extractImports(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                    PeImage& image) {
    ImportTable& table = image.imports;
    table.modules.clear();
    ImportBudget budget{limits.maxImportedModules, limits.maxImportedFunctions};

    if (image.declaredDirectory(pe::kImportDirectory) == nullptr) {
        table.status = image.directoryAbsence(pe::kImportDirectory);
    } else {
        for (const LIEF::PE::Import& descriptor : binary.imports()) {
            appendModule(descriptor, false, budget, table.modules);
        }
        table.status = table.modules.empty()
                           ? FieldStatus::parserError(
                                 "the import directory is declared, but no import descriptor "
                                 "could be read")
                           : FieldStatus::present();
    }
    const bool importsTruncated = budget.truncated;
    budget.truncated = false;

    if (image.declaredDirectory(pe::kDelayImportDirectory) == nullptr) {
        table.delayStatus = image.directoryAbsence(pe::kDelayImportDirectory);
    } else {
        const std::size_t before = table.modules.size();
        for (const LIEF::PE::DelayImport& descriptor : binary.delay_imports()) {
            appendModule(descriptor, true, budget, table.modules);
        }
        table.delayStatus = table.modules.size() == before && !budget.truncated
                                ? FieldStatus::parserError(
                                      "the delay import directory is declared, but no "
                                      "descriptor could be read")
                                : FieldStatus::present();
    }

    const auto note = std::format(
        "import limits reached ({} modules, {} functions); remaining entries were skipped",
        limits.maxImportedModules, limits.maxImportedFunctions);
    if (importsTruncated && table.status.hasData()) {
        table.status = FieldStatus::incomplete(note);
    }
    if (budget.truncated) {
        table.delayStatus = FieldStatus::incomplete(note);
    }
}

} // namespace sectoryn::lief_detail
