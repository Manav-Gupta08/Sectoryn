#include "parsers/LiefDetail.hpp"
#include "parsers/PeConstants.hpp"

#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/Export.hpp>
#include <LIEF/PE/ExportEntry.hpp>

#include <format>

namespace sectoryn::lief_detail {

void extractExports(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                    PeImage& image) {
    ExportTable& table = image.exports;
    table.functions.clear();

    if (image.declaredDirectory(pe::kExportDirectory) == nullptr) {
        table.status = image.directoryAbsence(pe::kExportDirectory);
        return;
    }

    const LIEF::PE::Export* source = binary.get_export();
    if (source == nullptr) {
        table.status = FieldStatus::parserError(
            "the export directory is declared, but it could not be read");
        return;
    }

    table.dllName = pe::escapeNonPrintable(source->name());
    table.timeDateStamp = source->timestamp();
    table.ordinalBase = source->ordinal_base();

    bool truncated = false;
    for (const LIEF::PE::ExportEntry& entry : source->entries()) {
        if (table.functions.size() == limits.maxExports) {
            truncated = true;
            break;
        }

        ExportedFunction function;
        function.name = pe::escapeNonPrintable(entry.name());
        function.ordinal = entry.ordinal();
        // address() is zero for forwarded entries; function_rva() always holds the table value.
        function.rva = entry.function_rva();
        if (entry.is_forwarded()) {
            function.forwarder = pe::escapeNonPrintable(entry.forward_information().key());
        }
        table.functions.push_back(std::move(function));
    }

    table.status = truncated ? FieldStatus::incomplete(std::format(
                                   "only the first {} exports were read", limits.maxExports))
                             : FieldStatus::present();
}

} // namespace sectoryn::lief_detail
