#include "analysis/FileIdentifier.hpp"
#include "support/TempDir.hpp"
#include "utilities/FileReader.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <utility>

namespace sectoryn {
namespace {

class FileIdentifierTest : public ::testing::Test {
protected:
    FileIdentification identify(std::string_view contents) {
        Result<FileReader> reader = FileReader::open(dir_.write("sample.bin", contents));
        if (!reader) {
            ADD_FAILURE() << reader.error().describe();
            return {};
        }
        Result<FileIdentification> id = identifyFile(reader.value());
        if (!id) {
            ADD_FAILURE() << id.error().describe();
            return {};
        }
        return std::move(id).value();
    }

private:
    test::TempDir dir_;
};

// Minimal DOS header: "MZ", zero padding, e_lfanew at 0x3C.
std::string dosHeader(std::uint32_t lfanew) {
    std::string header(0x40, '\0');
    header[0] = 'M';
    header[1] = 'Z';
    for (std::size_t i = 0; i < 4; ++i) {
        header[0x3C + i] = static_cast<char>((lfanew >> (8 * i)) & 0xFFU);
    }
    return header;
}

TEST_F(FileIdentifierTest, RecognizesPe) {
    const std::string data = dosHeader(0x40) + std::string("PE\0\0", 4) + std::string(20, '\0');
    const FileIdentification id = identify(data);
    EXPECT_EQ(id.kind, FileKind::Pe);
    EXPECT_EQ(id.peHeaderOffset, 0x40U);
}

TEST_F(FileIdentifierTest, AcceptsPeHeaderInsideDosHeader) {
    // Some packers overlap the PE header with the DOS header; the loader accepts this.
    std::string data = dosHeader(0x04);
    data.replace(4, 4, std::string("PE\0\0", 4));
    EXPECT_EQ(identify(data).kind, FileKind::Pe);
}

TEST_F(FileIdentifierTest, ExtensionDoesNotMatter) {
    EXPECT_EQ(identify("plain text that claims to be an exe").kind, FileKind::Unknown);
}

TEST_F(FileIdentifierTest, TruncatedDosHeader) {
    const FileIdentification id = identify("MZ\x90");
    EXPECT_EQ(id.kind, FileKind::MzWithoutPe);
    EXPECT_NE(id.detail.find("too small"), std::string::npos);
}

TEST_F(FileIdentifierTest, LfanewOutsideFile) {
    const FileIdentification id = identify(dosHeader(0xFFFFFFF0));
    EXPECT_EQ(id.kind, FileKind::MzWithoutPe);
    EXPECT_NE(id.detail.find("outside the file"), std::string::npos);
    EXPECT_FALSE(id.peHeaderOffset.has_value());
}

TEST_F(FileIdentifierTest, LfanewPointsAtLastBytes) {
    // Signature would straddle end of file.
    const std::string data = dosHeader(0x3E);
    EXPECT_EQ(identify(data).kind, FileKind::MzWithoutPe);
}

TEST_F(FileIdentifierTest, DosProgramWithoutPeSignature) {
    const std::string data = dosHeader(0x40) + std::string(16, 'x');
    EXPECT_EQ(identify(data).kind, FileKind::MzWithoutPe);
}

TEST_F(FileIdentifierTest, NeExecutable) {
    const FileIdentification id = identify(dosHeader(0x40) + "NE" + std::string(30, '\0'));
    EXPECT_EQ(id.kind, FileKind::MzWithoutPe);
    EXPECT_NE(id.detail.find("NE"), std::string::npos);
}

TEST_F(FileIdentifierTest, OtherFormats) {
    EXPECT_EQ(identify("\x7F"
                       "ELF\x02\x01\x01")
                  .kind,
              FileKind::Elf);
    EXPECT_EQ(identify("\xCF\xFA\xED\xFE\x07\x00\x00\x01").kind, FileKind::MachO);
    EXPECT_EQ(identify(std::string("\xCA\xFE\xBA\xBE\x00\x00\x00\x02", 8)).kind, FileKind::MachO);
    EXPECT_EQ(identify("PK\x03\x04rest").kind, FileKind::Zip);
    EXPECT_EQ(identify("%PDF-1.7").kind, FileKind::Pdf);
    EXPECT_EQ(identify("\x1F\x8B\x08").kind, FileKind::Gzip);
    EXPECT_EQ(identify("7z\xBC\xAF\x27\x1C").kind, FileKind::SevenZip);
    EXPECT_EQ(identify("Rar!\x1A\x07\x01").kind, FileKind::Rar);
    EXPECT_EQ(identify("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1").kind, FileKind::OleCompound);
}

TEST_F(FileIdentifierTest, JavaClassIsNotMachO) {
    // CAFEBABE followed by a class file version (major 52).
    const FileIdentification id = identify(std::string("\xCA\xFE\xBA\xBE\x00\x00\x00\x34", 8));
    EXPECT_EQ(id.kind, FileKind::Unknown);
}

TEST_F(FileIdentifierTest, EmptyFile) {
    EXPECT_EQ(identify("").kind, FileKind::Unknown);
}

TEST(FileKind, EveryKindHasName) {
    for (const FileKind kind :
         {FileKind::Unknown, FileKind::Pe, FileKind::MzWithoutPe, FileKind::Elf, FileKind::MachO,
          FileKind::Zip, FileKind::Pdf, FileKind::Gzip, FileKind::SevenZip, FileKind::Rar,
          FileKind::OleCompound}) {
        EXPECT_FALSE(toString(kind).empty());
    }
}

} // namespace
} // namespace sectoryn
