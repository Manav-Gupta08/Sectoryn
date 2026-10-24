#pragma once

#include "parsers/PeModel.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sectoryn::test {

struct BuilderSection {
    std::string name;
    std::uint32_t characteristics = 0;
    std::vector<std::byte> data;
    // 0 means "same as the data size".
    std::uint32_t virtualSize = 0;
};

struct BuilderImport {
    std::string dll;
    // A function written as "#123" is imported by ordinal.
    std::vector<std::string> functions;
};

// Writes small, well-formed PE files for tests, so no binary fixtures need to be checked in.
// Tests that need malformed input build a valid file first and then overwrite fields.
class PeBuilder {
public:
    static constexpr std::uint32_t kPeHeaderOffset = 0x80;
    static constexpr std::uint32_t kFileAlignment = 0x200;
    static constexpr std::uint32_t kSectionAlignment = 0x1000;
    static constexpr std::size_t kCoffHeaderOffset = kPeHeaderOffset + 4;
    static constexpr std::size_t kOptionalHeaderOffset = kCoffHeaderOffset + 20;

    static constexpr std::uint32_t kCode = 0x60000020;      // CNT_CODE | MEM_EXECUTE | MEM_READ
    static constexpr std::uint32_t kReadOnly = 0x40000040;  // CNT_INITIALIZED_DATA | MEM_READ
    static constexpr std::uint32_t kReadWrite = 0xC0000040; // ... | MEM_WRITE

    explicit PeBuilder(PeFormat format = PeFormat::Pe32);

    PeBuilder& machine(std::uint16_t value);
    PeBuilder& characteristics(std::uint16_t value);
    PeBuilder& timeDateStamp(std::uint32_t value);
    PeBuilder& subsystem(std::uint16_t value);
    PeBuilder& dllCharacteristics(std::uint16_t value);
    PeBuilder& imageBase(std::uint64_t value);
    // Defaults to the first section's RVA, or 0 when there are no sections.
    PeBuilder& entryPoint(std::uint32_t rva);
    PeBuilder& addSection(std::string name, std::uint32_t characteristics,
                          std::vector<std::byte> data, std::uint32_t virtualSize = 0);
    PeBuilder& addImport(std::string dll, std::vector<std::string> functions);
    PeBuilder& addDelayImport(std::string dll, std::vector<std::string> functions);
    PeBuilder& exports(std::string dllName, std::vector<std::string> functions);
    PeBuilder& overlay(std::vector<std::byte> data);

    [[nodiscard]] std::vector<std::byte> build() const;

    // Layout of build() output, for tests that overwrite header fields.
    [[nodiscard]] std::size_t optionalHeaderSize() const;
    [[nodiscard]] std::size_t dataDirectoryOffset(std::uint32_t index) const;
    [[nodiscard]] std::size_t sectionHeaderOffset(std::size_t index) const;
    // User sections first, then generated .idata, .didat and .edata, in that order.
    [[nodiscard]] std::size_t sectionCount() const;

private:
    PeFormat format_;
    std::uint16_t machine_;
    std::uint16_t characteristics_;
    std::uint32_t timeDateStamp_ = 0;
    std::uint16_t subsystem_ = 3;
    std::uint16_t dllCharacteristics_ = 0x0140;
    std::uint64_t imageBase_;
    std::optional<std::uint32_t> entryPoint_;
    std::vector<BuilderSection> sections_;
    std::vector<BuilderImport> imports_;
    std::vector<BuilderImport> delayImports_;
    std::string exportDll_;
    std::vector<std::string> exports_;
    std::vector<std::byte> overlay_;
};

void writeLe16(std::vector<std::byte>& data, std::size_t offset, std::uint16_t value);
void writeLe32(std::vector<std::byte>& data, std::size_t offset, std::uint32_t value);
void writeLe64(std::vector<std::byte>& data, std::size_t offset, std::uint64_t value);

[[nodiscard]] std::vector<std::byte> bytesOf(std::string_view text);

} // namespace sectoryn::test
