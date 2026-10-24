#include "support/PeBuilder.hpp"

#include <algorithm>
#include <array>
#include <span>
#include <stdexcept>
#include <utility>

namespace sectoryn::test {

namespace {

constexpr std::uint32_t kPe32OptionalHeaderSize = 224;
constexpr std::uint32_t kPe32PlusOptionalHeaderSize = 240;
constexpr std::uint32_t kPe32DataDirectoriesOffset = 96;
constexpr std::uint32_t kPe32PlusDataDirectoriesOffset = 112;
constexpr std::uint32_t kSectionHeaderSize = 40;
constexpr std::uint32_t kImportDescriptorSize = 20;
constexpr std::uint32_t kDelayDescriptorSize = 32;
constexpr std::uint32_t kExportDirectorySize = 40;
constexpr std::uint32_t kDataDirectoryCount = 16;
constexpr std::uint64_t kPe32OrdinalFlag = 0x80000000ULL;
constexpr std::uint64_t kPe32PlusOrdinalFlag = 0x8000000000000000ULL;

std::uint32_t alignTo(std::size_t value, std::uint32_t alignment) {
    return static_cast<std::uint32_t>((value + alignment - 1) / alignment * alignment);
}

std::uint32_t u32(std::size_t value) {
    return static_cast<std::uint32_t>(value);
}

std::size_t thunkSize(PeFormat format) {
    return format == PeFormat::Pe32Plus ? 8 : 4;
}

// Appends a NUL-terminated string padded to an even length and returns where it starts.
std::size_t appendString(std::vector<std::byte>& blob, std::string_view text) {
    const std::size_t offset = blob.size();
    for (const char c : text) {
        blob.push_back(static_cast<std::byte>(c));
    }
    blob.push_back(std::byte{0});
    if (blob.size() % 2 != 0) {
        blob.push_back(std::byte{0});
    }
    return offset;
}

void writeThunk(std::vector<std::byte>& blob, std::size_t offset, std::uint64_t value,
                PeFormat format) {
    if (format == PeFormat::Pe32Plus) {
        writeLe64(blob, offset, value);
    } else {
        writeLe32(blob, offset, static_cast<std::uint32_t>(value));
    }
}

// Returns the thunk value for one function, appending a hint/name entry when needed.
std::uint64_t importThunk(std::vector<std::byte>& blob, const std::string& function,
                          std::uint32_t base, PeFormat format) {
    if (function.starts_with('#')) {
        const std::uint64_t flag =
            format == PeFormat::Pe32Plus ? kPe32PlusOrdinalFlag : kPe32OrdinalFlag;
        return flag | std::stoul(function.substr(1));
    }
    const std::size_t hintOffset = blob.size();
    blob.push_back(std::byte{0});
    blob.push_back(std::byte{0});
    appendString(blob, function);
    return base + hintOffset;
}

struct Generated {
    std::vector<std::byte> data;
    std::uint32_t directorySize = 0;
    std::uint32_t iatOffset = 0;
    std::uint32_t iatSize = 0;
};

Generated buildImports(const std::vector<BuilderImport>& modules, std::uint32_t base,
                       PeFormat format) {
    const std::size_t ts = thunkSize(format);
    Generated out;
    out.directorySize = u32((modules.size() + 1) * kImportDescriptorSize);
    std::vector<std::byte>& blob = out.data;
    blob.resize(out.directorySize);

    std::vector<std::size_t> lookup;
    std::vector<std::size_t> addresses;
    for (const BuilderImport& entry : modules) {
        lookup.push_back(blob.size());
        blob.resize(blob.size() + (entry.functions.size() + 1) * ts);
    }
    out.iatOffset = u32(blob.size());
    for (const BuilderImport& entry : modules) {
        addresses.push_back(blob.size());
        blob.resize(blob.size() + (entry.functions.size() + 1) * ts);
    }
    out.iatSize = u32(blob.size()) - out.iatOffset;

    for (std::size_t i = 0; i < modules.size(); ++i) {
        const std::size_t descriptor = i * kImportDescriptorSize;
        const std::size_t name = appendString(blob, modules[i].dll);
        writeLe32(blob, descriptor, base + u32(lookup[i]));
        writeLe32(blob, descriptor + 12, base + u32(name));
        writeLe32(blob, descriptor + 16, base + u32(addresses[i]));
        for (std::size_t j = 0; j < modules[i].functions.size(); ++j) {
            const std::uint64_t thunk = importThunk(blob, modules[i].functions[j], base, format);
            writeThunk(blob, lookup[i] + j * ts, thunk, format);
            writeThunk(blob, addresses[i] + j * ts, thunk, format);
        }
    }
    return out;
}

Generated buildDelayImports(const std::vector<BuilderImport>& modules, std::uint32_t base,
                            PeFormat format) {
    constexpr std::size_t kHandleSlotSize = 8;
    const std::size_t ts = thunkSize(format);
    Generated out;
    out.directorySize = u32((modules.size() + 1) * kDelayDescriptorSize);
    std::vector<std::byte>& blob = out.data;
    blob.resize(out.directorySize);

    for (std::size_t i = 0; i < modules.size(); ++i) {
        const std::size_t count = modules[i].functions.size() + 1;
        const std::size_t handle = blob.size();
        const std::size_t names = handle + kHandleSlotSize;
        const std::size_t addresses = names + count * ts;
        blob.resize(addresses + count * ts);
        const std::size_t dll = appendString(blob, modules[i].dll);

        const std::size_t descriptor = i * kDelayDescriptorSize;
        writeLe32(blob, descriptor, 1); // RVA-based descriptor
        writeLe32(blob, descriptor + 4, base + u32(dll));
        writeLe32(blob, descriptor + 8, base + u32(handle));
        writeLe32(blob, descriptor + 12, base + u32(addresses));
        writeLe32(blob, descriptor + 16, base + u32(names));
        for (std::size_t j = 0; j + 1 < count; ++j) {
            const std::uint64_t thunk = importThunk(blob, modules[i].functions[j], base, format);
            writeThunk(blob, names + j * ts, thunk, format);
            writeThunk(blob, addresses + j * ts, thunk, format);
        }
    }
    return out;
}

// Function RVAs point into `codeBase`, which must not lie inside the export directory or the
// entries would be read as forwarders.
Generated buildExports(const std::string& dll, std::vector<std::string> names,
                       std::uint32_t base, std::uint32_t codeBase) {
    std::ranges::sort(names);
    const std::size_t count = names.size();
    Generated out;
    std::vector<std::byte>& blob = out.data;
    const std::size_t functions = kExportDirectorySize;
    const std::size_t namePointers = functions + count * 4;
    const std::size_t ordinals = namePointers + count * 4;
    blob.resize(ordinals + count * 2);
    const std::size_t dllName = appendString(blob, dll);

    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t name = appendString(blob, names[i]);
        writeLe32(blob, functions + i * 4, codeBase + u32(i * 16));
        writeLe32(blob, namePointers + i * 4, base + u32(name));
        writeLe16(blob, ordinals + i * 2, static_cast<std::uint16_t>(i));
    }
    writeLe32(blob, 12, base + u32(dllName));
    writeLe32(blob, 16, 1); // ordinal base
    writeLe32(blob, 20, u32(count));
    writeLe32(blob, 24, u32(count));
    writeLe32(blob, 28, base + u32(functions));
    writeLe32(blob, 32, base + u32(namePointers));
    writeLe32(blob, 36, base + u32(ordinals));
    out.directorySize = u32(blob.size());
    return out;
}

struct PlacedSection {
    const BuilderSection* source;
    std::uint32_t rva;
    std::uint32_t virtualSize;
    std::uint32_t rawOffset;
    std::uint32_t rawSize;
};

} // namespace

PeBuilder::PeBuilder(PeFormat format)
    : format_(format)
    , machine_(format == PeFormat::Pe32Plus ? 0x8664 : 0x014C)
    // EXECUTABLE_IMAGE plus LARGE_ADDRESS_AWARE (PE32+) or 32BIT_MACHINE (PE32).
    , characteristics_(format == PeFormat::Pe32Plus ? 0x0022 : 0x0102)
    , imageBase_(format == PeFormat::Pe32Plus ? 0x140000000ULL : 0x400000ULL) {}

PeBuilder& PeBuilder::machine(std::uint16_t value) {
    machine_ = value;
    return *this;
}

PeBuilder& PeBuilder::characteristics(std::uint16_t value) {
    characteristics_ = value;
    return *this;
}

PeBuilder& PeBuilder::timeDateStamp(std::uint32_t value) {
    timeDateStamp_ = value;
    return *this;
}

PeBuilder& PeBuilder::subsystem(std::uint16_t value) {
    subsystem_ = value;
    return *this;
}

PeBuilder& PeBuilder::dllCharacteristics(std::uint16_t value) {
    dllCharacteristics_ = value;
    return *this;
}

PeBuilder& PeBuilder::imageBase(std::uint64_t value) {
    imageBase_ = value;
    return *this;
}

PeBuilder& PeBuilder::entryPoint(std::uint32_t rva) {
    entryPoint_ = rva;
    return *this;
}

PeBuilder& PeBuilder::addSection(std::string name, std::uint32_t characteristics,
                                 std::vector<std::byte> data, std::uint32_t virtualSize) {
    sections_.push_back({std::move(name), characteristics, std::move(data), virtualSize});
    return *this;
}

PeBuilder& PeBuilder::addImport(std::string dll, std::vector<std::string> functions) {
    imports_.push_back({std::move(dll), std::move(functions)});
    return *this;
}

PeBuilder& PeBuilder::addDelayImport(std::string dll, std::vector<std::string> functions) {
    delayImports_.push_back({std::move(dll), std::move(functions)});
    return *this;
}

PeBuilder& PeBuilder::exports(std::string dllName, std::vector<std::string> functions) {
    exportDll_ = std::move(dllName);
    exports_ = std::move(functions);
    return *this;
}

PeBuilder& PeBuilder::overlay(std::vector<std::byte> data) {
    overlay_ = std::move(data);
    return *this;
}

std::size_t PeBuilder::optionalHeaderSize() const {
    return format_ == PeFormat::Pe32Plus ? kPe32PlusOptionalHeaderSize : kPe32OptionalHeaderSize;
}

std::size_t PeBuilder::dataDirectoryOffset(std::uint32_t index) const {
    const std::size_t table = format_ == PeFormat::Pe32Plus ? kPe32PlusDataDirectoriesOffset
                                                            : kPe32DataDirectoriesOffset;
    return kOptionalHeaderOffset + table + std::size_t{index} * 8;
}

std::size_t PeBuilder::sectionHeaderOffset(std::size_t index) const {
    return kOptionalHeaderOffset + optionalHeaderSize() + index * kSectionHeaderSize;
}

std::size_t PeBuilder::sectionCount() const {
    return sections_.size() + (imports_.empty() ? 0 : 1) + (delayImports_.empty() ? 0 : 1) +
           (exports_.empty() ? 0 : 1);
}

std::vector<std::byte> PeBuilder::build() const {
    const std::size_t headersEnd = sectionHeaderOffset(sectionCount());
    const std::uint32_t sizeOfHeaders = alignTo(headersEnd, kFileAlignment);
    if (sizeOfHeaders > kSectionAlignment) {
        throw std::logic_error("too many sections for the builder's fixed layout");
    }

    std::vector<BuilderSection> generated;
    // place() keeps pointers into this vector; it never holds more than three sections.
    generated.reserve(3);
    std::vector<PlacedSection> placed;
    std::uint32_t nextRva = kSectionAlignment;
    std::uint32_t nextRaw = sizeOfHeaders;
    const auto place = [&](const BuilderSection& section) {
        const std::uint32_t virtualSize =
            section.virtualSize != 0 ? section.virtualSize : u32(section.data.size());
        const std::uint32_t rawSize = alignTo(section.data.size(), kFileAlignment);
        placed.push_back({&section, nextRva, virtualSize, rawSize != 0 ? nextRaw : 0, rawSize});
        nextRaw += rawSize;
        nextRva += alignTo(std::max<std::size_t>({virtualSize, rawSize, 1}), kSectionAlignment);
    };
    for (const BuilderSection& section : sections_) {
        place(section);
    }

    std::array<DataDirectory, kDataDirectoryCount> directories{};
    if (!imports_.empty()) {
        const Generated table = buildImports(imports_, nextRva, format_);
        directories[1] = {1, nextRva, table.directorySize};
        directories[12] = {12, nextRva + table.iatOffset, table.iatSize};
        generated.push_back({".idata", kReadWrite, table.data, 0});
        place(generated.back());
    }
    if (!delayImports_.empty()) {
        const Generated table = buildDelayImports(delayImports_, nextRva, format_);
        directories[13] = {13, nextRva, table.directorySize};
        generated.push_back({".didat", kReadWrite, table.data, 0});
        place(generated.back());
    }
    if (!exports_.empty()) {
        if (sections_.empty()) {
            throw std::logic_error("exports need a section for the function addresses");
        }
        const Generated table = buildExports(exportDll_, exports_, nextRva, placed.front().rva);
        directories[0] = {0, nextRva, table.directorySize};
        generated.push_back({".edata", kReadOnly, table.data, 0});
        place(generated.back());
    }

    std::vector<std::byte> file(nextRaw);
    file[0] = std::byte{'M'};
    file[1] = std::byte{'Z'};
    writeLe32(file, 0x3C, kPeHeaderOffset);
    writeLe32(file, kPeHeaderOffset, 0x00004550); // "PE\0\0"

    writeLe16(file, kCoffHeaderOffset, machine_);
    writeLe16(file, kCoffHeaderOffset + 2, static_cast<std::uint16_t>(placed.size()));
    writeLe32(file, kCoffHeaderOffset + 4, timeDateStamp_);
    writeLe16(file, kCoffHeaderOffset + 16, static_cast<std::uint16_t>(optionalHeaderSize()));
    writeLe16(file, kCoffHeaderOffset + 18, characteristics_);

    std::uint32_t sizeOfCode = 0;
    std::uint32_t sizeOfData = 0;
    std::uint32_t baseOfCode = 0;
    for (const PlacedSection& section : placed) {
        if ((section.source->characteristics & 0x20U) != 0) {
            sizeOfCode += section.rawSize;
            baseOfCode = baseOfCode == 0 ? section.rva : baseOfCode;
        } else {
            sizeOfData += section.rawSize;
        }
    }
    const std::uint32_t entry = entryPoint_.value_or(placed.empty() ? 0 : placed.front().rva);

    const std::size_t opt = kOptionalHeaderOffset;
    const bool plus = format_ == PeFormat::Pe32Plus;
    writeLe16(file, opt, plus ? 0x20B : 0x10B);
    file[opt + 2] = std::byte{14};
    writeLe32(file, opt + 4, sizeOfCode);
    writeLe32(file, opt + 8, sizeOfData);
    writeLe32(file, opt + 16, entry);
    writeLe32(file, opt + 20, baseOfCode);
    if (plus) {
        writeLe64(file, opt + 24, imageBase_);
    } else {
        writeLe32(file, opt + 28, static_cast<std::uint32_t>(imageBase_));
    }
    writeLe32(file, opt + 32, kSectionAlignment);
    writeLe32(file, opt + 36, kFileAlignment);
    writeLe16(file, opt + 40, 6);
    writeLe16(file, opt + 48, 6);
    writeLe32(file, opt + 56, nextRva);
    writeLe32(file, opt + 60, sizeOfHeaders);
    writeLe16(file, opt + 68, subsystem_);
    writeLe16(file, opt + 70, dllCharacteristics_);
    if (plus) {
        writeLe64(file, opt + 72, 0x100000);
        writeLe64(file, opt + 80, 0x1000);
        writeLe64(file, opt + 88, 0x100000);
        writeLe64(file, opt + 96, 0x1000);
        writeLe32(file, opt + 108, kDataDirectoryCount);
    } else {
        writeLe32(file, opt + 72, 0x100000);
        writeLe32(file, opt + 76, 0x1000);
        writeLe32(file, opt + 80, 0x100000);
        writeLe32(file, opt + 84, 0x1000);
        writeLe32(file, opt + 92, kDataDirectoryCount);
    }
    for (std::uint32_t i = 0; i < kDataDirectoryCount; ++i) {
        writeLe32(file, dataDirectoryOffset(i), directories[i].rva);
        writeLe32(file, dataDirectoryOffset(i) + 4, directories[i].size);
    }

    for (std::size_t i = 0; i < placed.size(); ++i) {
        const PlacedSection& section = placed[i];
        const std::size_t header = sectionHeaderOffset(i);
        const std::string& name = section.source->name;
        const std::size_t nameLength = std::min<std::size_t>(name.size(), 8);
        std::ranges::copy(std::as_bytes(std::span(name)).first(nameLength),
                          file.begin() + static_cast<std::ptrdiff_t>(header));
        writeLe32(file, header + 8, section.virtualSize);
        writeLe32(file, header + 12, section.rva);
        writeLe32(file, header + 16, section.rawSize);
        writeLe32(file, header + 20, section.rawOffset);
        writeLe32(file, header + 36, section.source->characteristics);
        std::ranges::copy(section.source->data,
                          file.begin() + static_cast<std::ptrdiff_t>(section.rawOffset));
    }

    file.insert(file.end(), overlay_.begin(), overlay_.end());
    return file;
}

void writeLe16(std::vector<std::byte>& data, std::size_t offset, std::uint16_t value) {
    for (std::size_t i = 0; i < 2; ++i) {
        data.at(offset + i) = static_cast<std::byte>((value >> (8 * i)) & 0xFFU);
    }
}

void writeLe32(std::vector<std::byte>& data, std::size_t offset, std::uint32_t value) {
    for (std::size_t i = 0; i < 4; ++i) {
        data.at(offset + i) = static_cast<std::byte>((value >> (8 * i)) & 0xFFU);
    }
}

void writeLe64(std::vector<std::byte>& data, std::size_t offset, std::uint64_t value) {
    for (std::size_t i = 0; i < 8; ++i) {
        data.at(offset + i) = static_cast<std::byte>((value >> (8 * i)) & 0xFFU);
    }
}

std::vector<std::byte> bytesOf(std::string_view text) {
    const auto bytes = std::as_bytes(std::span(text));
    return {bytes.begin(), bytes.end()};
}

} // namespace sectoryn::test
