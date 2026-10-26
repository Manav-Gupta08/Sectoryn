#include "reports/ReportCommon.hpp"

#include <exception>
#include <format>

namespace sectoryn {

namespace {

// 2000-01-01 and 2100-01-01 UTC.
constexpr std::uint32_t kPlausibleFrom = 946684800;
constexpr std::uint64_t kPlausibleUntil = 4102444800;

std::string toUtf8(const std::filesystem::path& path) {
    try {
        const std::u8string text = path.u8string();
        return {text.begin(), text.end()};
    } catch (const std::exception&) {
        // Windows paths may hold unpaired UTF-16 surrogates, which have no UTF-8 form.
        return "(file name not representable as UTF-8)";
    }
}

} // namespace

std::string reportedFileName(const FileMetadata& file, const ReportOptions& options) {
    return reportedPath(file.path, options);
}

std::string reportedPath(const std::filesystem::path& path, const ReportOptions& options) {
    return toUtf8(options.includeFilePath ? path : path.filename());
}

std::string formatUtc(std::chrono::system_clock::time_point time) {
    return std::format("{:%FT%T}Z", std::chrono::floor<std::chrono::milliseconds>(time));
}

std::string formatCoffTimestamp(std::uint32_t seconds) {
    if (seconds == 0) {
        return "0 (not set)";
    }
    if (seconds < kPlausibleFrom || seconds >= kPlausibleUntil) {
        return std::format("0x{:08X} (not a plausible date; possibly a reproducible-build hash)",
                           seconds);
    }
    const std::chrono::sys_seconds time{std::chrono::seconds{seconds}};
    return std::format("{:%F %T} UTC (0x{:08X})", time, seconds);
}

std::string_view reportToken(FieldState state) noexcept {
    switch (state) {
    case FieldState::NotInspected:
        return "not_inspected";
    case FieldState::Present:
        return "present";
    case FieldState::Absent:
        return "absent";
    case FieldState::Invalid:
        return "invalid";
    case FieldState::Unsupported:
        return "unsupported";
    case FieldState::ParserError:
        return "parser_error";
    case FieldState::Incomplete:
        return "incomplete";
    }
    return "unknown";
}

std::string_view reportToken(TriageOutcome outcome) noexcept {
    switch (outcome) {
    case TriageOutcome::NoSignificantIndicators:
        return "no_significant_indicators";
    case TriageOutcome::SuspiciousIndicators:
        return "suspicious_indicators";
    case TriageOutcome::HighPriority:
        return "high_priority";
    case TriageOutcome::AnalysisIncomplete:
        return "analysis_incomplete";
    case TriageOutcome::UnsupportedOrInvalid:
        return "unsupported_or_invalid";
    }
    return "unknown";
}

std::string_view reportToken(Severity severity) noexcept {
    switch (severity) {
    case Severity::Informational:
        return "informational";
    case Severity::Low:
        return "low";
    case Severity::Medium:
        return "medium";
    case Severity::High:
        return "high";
    case Severity::Critical:
        return "critical";
    }
    return "unknown";
}

std::string_view reportToken(Confidence confidence) noexcept {
    switch (confidence) {
    case Confidence::Low:
        return "low";
    case Confidence::Medium:
        return "medium";
    case Confidence::High:
        return "high";
    }
    return "unknown";
}

std::string_view reportToken(FileKind kind) noexcept {
    switch (kind) {
    case FileKind::Unknown:
        return "unknown";
    case FileKind::Pe:
        return "pe";
    case FileKind::MzWithoutPe:
        return "mz_without_pe";
    case FileKind::Elf:
        return "elf";
    case FileKind::MachO:
        return "mach_o";
    case FileKind::Zip:
        return "zip";
    case FileKind::Pdf:
        return "pdf";
    case FileKind::Gzip:
        return "gzip";
    case FileKind::SevenZip:
        return "7z";
    case FileKind::Rar:
        return "rar";
    case FileKind::OleCompound:
        return "ole_compound";
    }
    return "unknown";
}

std::string_view reportToken(PeFormat format) noexcept {
    switch (format) {
    case PeFormat::Pe32:
        return "pe32";
    case PeFormat::Pe32Plus:
        return "pe32_plus";
    }
    return "unknown";
}

std::string_view reportToken(SectionDataAvailability availability) noexcept {
    switch (availability) {
    case SectionDataAvailability::None:
        return "none";
    case SectionDataAvailability::Full:
        return "full";
    case SectionDataAvailability::Truncated:
        return "truncated";
    case SectionDataAvailability::OutsideFile:
        return "outside_file";
    }
    return "unknown";
}

std::string_view reportToken(SectionAnomalyKind kind) noexcept {
    switch (kind) {
    case SectionAnomalyKind::WritableAndExecutable:
        return "writable_and_executable";
    case SectionAnomalyKind::ExecutableWithoutCodeFlag:
        return "executable_without_code_flag";
    case SectionAnomalyKind::SharedAndWritable:
        return "shared_and_writable";
    case SectionAnomalyKind::RawDataOutsideFile:
        return "raw_data_outside_file";
    case SectionAnomalyKind::RawDataTruncated:
        return "raw_data_truncated";
    case SectionAnomalyKind::RawDataInHeaders:
        return "raw_data_in_headers";
    case SectionAnomalyKind::RawDataOverlap:
        return "raw_data_overlap";
    case SectionAnomalyKind::VirtualRangeOverlap:
        return "virtual_range_overlap";
    case SectionAnomalyKind::VirtualAddressOutOfOrder:
        return "virtual_address_out_of_order";
    case SectionAnomalyKind::VirtualAddressMisaligned:
        return "virtual_address_misaligned";
    case SectionAnomalyKind::RawOffsetMisaligned:
        return "raw_offset_misaligned";
    case SectionAnomalyKind::BeyondSizeOfImage:
        return "beyond_size_of_image";
    case SectionAnomalyKind::EmptyName:
        return "empty_name";
    case SectionAnomalyKind::NonPrintableName:
        return "non_printable_name";
    case SectionAnomalyKind::PackerSectionName:
        return "packer_section_name";
    }
    return "unknown";
}

std::string_view reportToken(IndicatorKind kind) noexcept {
    switch (kind) {
    case IndicatorKind::Url:
        return "url";
    case IndicatorKind::Domain:
        return "domain";
    case IndicatorKind::IpV4Address:
        return "ipv4_address";
    case IndicatorKind::FilePath:
        return "file_path";
    case IndicatorKind::UncPath:
        return "unc_path";
    case IndicatorKind::RegistryKey:
        return "registry_key";
    case IndicatorKind::PowerShell:
        return "powershell";
    case IndicatorKind::CommandLine:
        return "command_line";
    case IndicatorKind::Persistence:
        return "persistence";
    case IndicatorKind::EncodedData:
        return "encoded_data";
    }
    return "unknown";
}

std::string_view reportToken(StringEncoding encoding) noexcept {
    switch (encoding) {
    case StringEncoding::Ascii:
        return "ascii";
    case StringEncoding::Utf16Le:
        return "utf16le";
    }
    return "unknown";
}

} // namespace sectoryn
