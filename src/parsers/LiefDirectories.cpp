#include "parsers/LiefDetail.hpp"
#include "parsers/PeConstants.hpp"

#include <LIEF/PE/Binary.hpp>
#include <LIEF/PE/Parser.hpp>
#include <LIEF/PE/ResourceData.hpp>
#include <LIEF/PE/ResourceNode.hpp>
#include <LIEF/PE/TLS.hpp>
#include <LIEF/PE/debug/CodeViewPDB.hpp>
#include <LIEF/PE/debug/Debug.hpp>

#include <array>
#include <format>
#include <vector>

namespace sectoryn::lief_detail {

namespace {

// Standard resource trees are root -> type -> name -> language -> data.
constexpr std::uint32_t kTypeLevel = 1;
constexpr std::uint32_t kNameLevel = 2;
constexpr std::uint32_t kLanguageLevel = 3;

ResourceEntry::Key keyOf(const LIEF::PE::ResourceNode& node) {
    ResourceEntry::Key key;
    if (node.has_name()) {
        key.name = pe::escapeNonPrintable(node.utf8_name());
    } else {
        key.id = node.id();
    }
    return key;
}

} // namespace

void extractResources(const LIEF::PE::Binary& binary, const AnalysisLimits& limits,
                      PeImage& image) {
    ResourceTable& table = image.resources;
    table.entries.clear();
    table.directoryCount = 0;

    if (image.declaredDirectory(pe::kResourceDirectory) == nullptr) {
        table.status = image.directoryAbsence(pe::kResourceDirectory);
        return;
    }
    const LIEF::PE::ResourceNode* root = binary.resources();
    if (root == nullptr) {
        table.status = FieldStatus::parserError(
            "the resource directory is declared, but the resource tree could not be read");
        return;
    }

    // Iterative walk: a crafted tree can be deep, and the walk must not grow the call stack.
    struct Pending {
        const LIEF::PE::ResourceNode* node;
        std::array<ResourceEntry::Key, kLanguageLevel + 1> path;
    };
    std::vector<Pending> stack{{root, {}}};
    bool truncated = false;

    while (!stack.empty()) {
        Pending current = std::move(stack.back());
        stack.pop_back();
        const LIEF::PE::ResourceNode& node = *current.node;
        const std::uint32_t depth = node.depth();
        if (depth >= kTypeLevel && depth <= kLanguageLevel) {
            current.path[depth] = keyOf(node);
        }

        if (const auto* data = node.cast<LIEF::PE::ResourceData>(); data != nullptr) {
            if (table.entries.size() == limits.maxResourceEntries) {
                truncated = true;
                break;
            }
            table.entries.push_back({
                .type = current.path[kTypeLevel],
                .name = current.path[kNameLevel],
                .language = current.path[kLanguageLevel],
                .fileOffset = data->offset(),
                .size = static_cast<std::uint32_t>(data->content().size()),
                .codePage = data->code_page(),
            });
            continue;
        }

        ++table.directoryCount;
        for (const LIEF::PE::ResourceNode& child : node.childs()) {
            stack.push_back({&child, current.path});
        }
    }

    table.status = truncated ? FieldStatus::incomplete(std::format(
                                   "only the first {} resources were read",
                                   limits.maxResourceEntries))
                             : FieldStatus::present();
}

void extractDebug(const LIEF::PE::Binary& binary, PeImage& image) {
    DebugDirectory& directory = image.debug;
    directory.entries.clear();

    if (image.declaredDirectory(pe::kDebugDirectory) == nullptr) {
        directory.status = image.directoryAbsence(pe::kDebugDirectory);
        return;
    }

    for (const LIEF::PE::Debug& source : binary.debug()) {
        DebugEntry entry;
        entry.type = static_cast<std::uint32_t>(source.type());
        entry.timeDateStamp = source.timestamp();
        entry.sizeOfData = source.sizeof_data();
        entry.addressOfRawData = source.addressof_rawdata();
        entry.pointerToRawData = source.pointerto_rawdata();
        if (const auto* pdb = source.as<LIEF::PE::CodeViewPDB>(); pdb != nullptr) {
            entry.pdbPath = pe::escapeNonPrintable(pdb->filename());
        }
        directory.entries.push_back(std::move(entry));
    }

    directory.status = directory.entries.empty()
                           ? FieldStatus::parserError(
                                 "the debug directory is declared, but no entry could be read")
                           : FieldStatus::present();
}

void extractTls(const LIEF::PE::Binary& binary, PeImage& image) {
    TlsDirectory& tls = image.tls;
    tls.callbacks.clear();

    if (image.declaredDirectory(pe::kTlsDirectory) == nullptr) {
        tls.status = image.directoryAbsence(pe::kTlsDirectory);
        return;
    }
    const LIEF::PE::TLS* source = binary.tls();
    if (source == nullptr) {
        tls.status = FieldStatus::parserError(
            "the TLS directory is declared, but it could not be read");
        return;
    }

    const auto& [rawStart, rawEnd] = source->addressof_raw_data();
    tls.startAddressOfRawData = rawStart;
    tls.endAddressOfRawData = rawEnd;
    tls.addressOfIndex = source->addressof_index();
    tls.addressOfCallbacks = source->addressof_callbacks();
    tls.sizeOfZeroFill = source->sizeof_zero_fill();
    tls.characteristics = source->characteristics();
    tls.callbacks = source->callbacks();
    tls.status = tls.callbacks.size() >= LIEF::PE::Parser::MAX_TLS_CALLBACKS
                     ? FieldStatus::incomplete(std::format(
                           "the parser stops after {} TLS callbacks",
                           LIEF::PE::Parser::MAX_TLS_CALLBACKS))
                     : FieldStatus::present();
}

} // namespace sectoryn::lief_detail
