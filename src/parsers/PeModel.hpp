#pragma once

#include "parsers/FieldStatus.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Plain data describing a parsed PE file. Values are copied as declared in the file; nothing
// here has been checked for consistency unless a FieldStatus or StructuralIssue says so.

namespace sectoryn {

enum class PeFormat : std::uint8_t { Pe32, Pe32Plus };

struct DosHeader {
    std::uint16_t magic = 0;
    std::uint16_t bytesOnLastPage = 0;
    std::uint16_t pagesInFile = 0;
    std::uint16_t relocations = 0;
    std::uint16_t headerParagraphs = 0;
    std::uint16_t minExtraParagraphs = 0;
    std::uint16_t maxExtraParagraphs = 0;
    std::uint16_t initialSs = 0;
    std::uint16_t initialSp = 0;
    std::uint16_t checksum = 0;
    std::uint16_t initialIp = 0;
    std::uint16_t initialCs = 0;
    std::uint16_t relocationTableOffset = 0;
    std::uint16_t overlayNumber = 0;
    std::uint16_t oemId = 0;
    std::uint16_t oemInfo = 0;
    std::uint32_t peHeaderOffset = 0;
};

struct CoffHeader {
    std::uint16_t machine = 0;
    std::uint16_t numberOfSections = 0;
    std::uint32_t timeDateStamp = 0;
    std::uint32_t pointerToSymbolTable = 0;
    std::uint32_t numberOfSymbols = 0;
    std::uint16_t sizeOfOptionalHeader = 0;
    std::uint16_t characteristics = 0;
};

struct OptionalHeader {
    std::uint16_t magic = 0;
    std::uint8_t majorLinkerVersion = 0;
    std::uint8_t minorLinkerVersion = 0;
    std::uint32_t sizeOfCode = 0;
    std::uint32_t sizeOfInitializedData = 0;
    std::uint32_t sizeOfUninitializedData = 0;
    std::uint32_t addressOfEntryPoint = 0;
    std::uint32_t baseOfCode = 0;
    // Only PE32 has this field.
    std::optional<std::uint32_t> baseOfData;
    std::uint64_t imageBase = 0;
    std::uint32_t sectionAlignment = 0;
    std::uint32_t fileAlignment = 0;
    std::uint16_t majorOperatingSystemVersion = 0;
    std::uint16_t minorOperatingSystemVersion = 0;
    std::uint16_t majorImageVersion = 0;
    std::uint16_t minorImageVersion = 0;
    std::uint16_t majorSubsystemVersion = 0;
    std::uint16_t minorSubsystemVersion = 0;
    std::uint32_t win32VersionValue = 0;
    std::uint32_t sizeOfImage = 0;
    std::uint32_t sizeOfHeaders = 0;
    std::uint32_t checksum = 0;
    std::uint16_t subsystem = 0;
    std::uint16_t dllCharacteristics = 0;
    std::uint64_t sizeOfStackReserve = 0;
    std::uint64_t sizeOfStackCommit = 0;
    std::uint64_t sizeOfHeapReserve = 0;
    std::uint64_t sizeOfHeapCommit = 0;
    std::uint32_t loaderFlags = 0;
    std::uint32_t numberOfRvaAndSizes = 0;
};

struct DataDirectory {
    std::uint32_t index = 0;
    // For the certificate table this is a file offset, not an RVA.
    std::uint32_t rva = 0;
    std::uint32_t size = 0;

    [[nodiscard]] bool isEmpty() const noexcept { return rva == 0 && size == 0; }
};

struct Section {
    // The 8 name bytes exactly as stored.
    std::array<std::uint8_t, 8> rawName{};
    // Printable form of rawName: trailing NULs dropped, other non-printable bytes escaped.
    std::string name;
    std::uint32_t virtualAddress = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t pointerToRawData = 0;
    std::uint32_t sizeOfRawData = 0;
    std::uint32_t pointerToRelocations = 0;
    std::uint32_t pointerToLineNumbers = 0;
    std::uint16_t numberOfRelocations = 0;
    std::uint16_t numberOfLineNumbers = 0;
    std::uint32_t characteristics = 0;
};

struct ImportedFunction {
    // Empty when imported by ordinal only.
    std::string name;
    std::optional<std::uint16_t> ordinal;
    std::uint16_t hint = 0;
};

struct ImportedModule {
    std::string name;
    bool delayLoaded = false;
    std::vector<ImportedFunction> functions;
};

struct ImportTable {
    FieldStatus status;
    FieldStatus delayStatus;
    std::vector<ImportedModule> modules;
};

struct ExportedFunction {
    // Empty for exports that have an ordinal but no name.
    std::string name;
    std::uint32_t ordinal = 0;
    std::uint32_t rva = 0;
    // "library.function" for forwarded exports.
    std::optional<std::string> forwarder;
};

struct ExportTable {
    FieldStatus status;
    std::string dllName;
    std::uint32_t timeDateStamp = 0;
    std::uint32_t ordinalBase = 0;
    std::vector<ExportedFunction> functions;
};

struct ResourceEntry {
    // Each level is either a numeric ID or a name taken from the file.
    struct Key {
        std::optional<std::uint32_t> id;
        std::string name;
    };
    Key type;
    Key name;
    Key language;
    std::uint64_t fileOffset = 0;
    std::uint32_t size = 0;
    std::uint32_t codePage = 0;
};

struct ResourceTable {
    FieldStatus status;
    std::vector<ResourceEntry> entries;
    std::uint32_t directoryCount = 0;
};

struct DebugEntry {
    std::uint32_t type = 0;
    std::uint32_t timeDateStamp = 0;
    std::uint32_t sizeOfData = 0;
    std::uint32_t addressOfRawData = 0;
    std::uint32_t pointerToRawData = 0;
    // Set for CodeView PDB 7.0 records.
    std::optional<std::string> pdbPath;
};

struct DebugDirectory {
    FieldStatus status;
    std::vector<DebugEntry> entries;
};

struct TlsDirectory {
    FieldStatus status;
    std::uint64_t startAddressOfRawData = 0;
    std::uint64_t endAddressOfRawData = 0;
    std::uint64_t addressOfIndex = 0;
    std::uint64_t addressOfCallbacks = 0;
    std::uint32_t sizeOfZeroFill = 0;
    std::uint32_t characteristics = 0;
    // Virtual addresses, not RVAs.
    std::vector<std::uint64_t> callbacks;
};

struct CertificateTable {
    FieldStatus status;
    std::uint32_t fileOffset = 0;
    std::uint32_t size = 0;
};

struct Overlay {
    FieldStatus status;
    std::uint64_t fileOffset = 0;
    std::uint64_t size = 0;
    // The certificate table normally sits after the last section, inside this range.
    bool containsCertificateTable = false;
};

// A header-level inconsistency. `code` is stable and meant for detection rules; `message` is
// for people.
struct StructuralIssue {
    std::string code;
    std::string message;
};

struct PeImage {
    PeFormat format = PeFormat::Pe32;
    std::uint64_t fileSize = 0;

    DosHeader dos;
    CoffHeader coff;
    OptionalHeader optional;
    std::vector<DataDirectory> dataDirectories;

    FieldStatus sectionTable;
    std::vector<Section> sections;

    ImportTable imports;
    ExportTable exports;
    ResourceTable resources;
    DebugDirectory debug;
    TlsDirectory tls;
    CertificateTable certificate;
    Overlay overlay;

    std::vector<StructuralIssue> issues;

    // Null when the entry is all zero, lies beyond NumberOfRvaAndSizes, or could not be read.
    [[nodiscard]] const DataDirectory* declaredDirectory(std::uint32_t index) const noexcept {
        if (index >= dataDirectories.size() || dataDirectories[index].isEmpty()) {
            return nullptr;
        }
        return &dataDirectories[index];
    }

    // Explains why declaredDirectory(index) returned null.
    [[nodiscard]] FieldStatus directoryAbsence(std::uint32_t index) const {
        if (index >= optional.numberOfRvaAndSizes) {
            return FieldStatus::absent("not covered by NumberOfRvaAndSizes");
        }
        if (index >= dataDirectories.size()) {
            return FieldStatus::invalid("the data directory entry lies past the end of the file");
        }
        return FieldStatus::absent("the data directory entry is empty");
    }
};

} // namespace sectoryn
