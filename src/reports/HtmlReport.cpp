#include "reports/HtmlReport.hpp"

#include "analysis/SectionCharacteristics.hpp"
#include "parsers/PeConstants.hpp"
#include "reports/HtmlEscape.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <initializer_list>
#include <numeric>
#include <optional>
#include <string>
#include <vector>

namespace sectoryn {

namespace {

constexpr double kMaxEntropy = 8.0;

std::string hex(std::uint64_t value, int digits = 0) {
    return std::format("0x{:0{}X}", value, digits);
}

std::string byteSize(std::uint64_t bytes) {
    if (bytes < 1024) {
        return std::format("{} bytes", bytes);
    }
    constexpr std::array<std::string_view, 3> kUnits = {"KiB", "MiB", "GiB"};
    double value = static_cast<double>(bytes) / 1024.0;
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < kUnits.size()) {
        value /= 1024.0;
        ++unit;
    }
    return std::format("{:.1f} {} ({} bytes)", value, kUnits[unit], bytes);
}

std::string statusText(const FieldStatus& status) {
    std::string text(toString(status.state));
    if (!status.detail.empty()) {
        text += ": ";
        text += status.detail;
    }
    return text;
}

std::string entropyText(const RangeEntropy& range) {
    return range.entropy ? std::format("{:.3f}", *range.entropy) : std::string("-");
}

std::string joined(const std::vector<std::string>& parts) {
    std::string text;
    for (const std::string& part : parts) {
        if (!text.empty()) {
            text += ", ";
        }
        text += part;
    }
    return text;
}

// Builds the document. Markup comes only from literals in this file; everything else goes
// through text(), which escapes it.
class Html {
public:
    struct Column {
        std::string_view title;
        // Class applied to every cell of the column, e.g. "num" for right-aligned numbers.
        std::string_view cls = {};
    };

    void raw(std::string_view markup) { out_ += markup; }
    void text(std::string_view content) { appendHtmlEscaped(out_, content); }

    void element(std::string_view tag, std::string_view content, std::string_view cls = {}) {
        open(tag, cls);
        text(content);
        close(tag);
    }

    void open(std::string_view tag, std::string_view cls = {}) {
        out_ += '<';
        out_ += tag;
        if (!cls.empty()) {
            out_ += " class=\"";
            out_ += cls;
            out_ += '"';
        }
        out_ += '>';
    }

    void close(std::string_view tag) {
        out_ += "</";
        out_ += tag;
        out_ += '>';
    }

    void heading(std::string_view title, std::string_view id) {
        out_ += "<h2 id=\"";
        out_ += id;
        out_ += "\">";
        text(title);
        out_ += "</h2>";
    }

    void paragraph(std::string_view content, std::string_view cls = {}) {
        element("p", content, cls);
    }

    void beginTable(std::initializer_list<Column> columns, std::string_view cls = {}) {
        columns_.assign(columns.begin(), columns.end());
        open("table", cls);
        raw("<thead><tr>");
        for (const Column& column : columns_) {
            element("th", column.title, column.cls);
        }
        raw("</tr></thead><tbody>");
    }

    void row(std::initializer_list<std::string_view> cells, std::string_view cls = {}) {
        open("tr", cls);
        std::size_t index = 0;
        for (const std::string_view cell : cells) {
            element("td", cell, index < columns_.size() ? columns_[index].cls : std::string_view{});
            ++index;
        }
        close("tr");
    }

    void endTable() {
        raw("</tbody></table>");
        columns_.clear();
    }

    void beginFacts() { raw("<table class=\"facts\"><tbody>"); }
    void fact(std::string_view label, std::string_view value) {
        raw("<tr>");
        element("th", label);
        element("td", value);
        raw("</tr>");
    }
    void endFacts() { raw("</tbody></table>"); }

    void list(const std::vector<std::string>& items) {
        raw("<ul>");
        for (const std::string& item : items) {
            element("li", item);
        }
        raw("</ul>");
    }

    [[nodiscard]] std::string take() { return std::move(out_); }

private:
    std::string out_;
    std::vector<Column> columns_;
};

void writeHead(Html& html, const AnalysisResult& result, const ReportOptions& options) {
    html.raw("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
             "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; "
             "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">\n"
             "<meta name=\"referrer\" content=\"no-referrer\">\n"
             "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
             "<meta name=\"generator\" content=\"Sectoryn ");
    html.text(result.engine.version);
    html.raw("\">\n<title>");
    html.text("Sectoryn report: " + reportedFileName(result.file, options));
    html.raw("</title>\n<style>\n");
    html.raw(htmlReportStyleSheet());
    html.raw("</style>\n</head>\n<body>\n");
}

void writeBanner(Html& html, const AnalysisResult& result, const ReportOptions& options) {
    const RiskAssessment& risk = result.risk;
    html.raw("<header class=\"banner\">");
    html.paragraph("Sectoryn static analysis report", "eyebrow");
    html.element("h1", reportedFileName(result.file, options));
    html.paragraph(result.sha256, "hash");
    html.raw("<div class=\"verdict\">");
    html.element("span", toString(risk.outcome),
                 std::format("outcome outcome-{}", reportToken(risk.outcome)));
    if (risk.outcome != TriageOutcome::UnsupportedOrInvalid) {
        html.raw(" ");
        html.element("span", std::format("Score {:.1f} / {:.0f}", risk.score,
                                         RiskAssessment::kMaxScore),
                     "score");
    }
    html.raw("</div></header>\n");
    html.paragraph("Static analysis reads the file without running it. The outcome ranks the "
                   "file for attention; it is not a verdict that the file is malicious or safe.",
                   "notice");
}

void writeContents(Html& html, const AnalysisResult& result, const ReportOptions& options) {
    struct Entry {
        std::string_view id;
        std::string_view title;
        bool shown;
    };
    const bool hasPe = result.pe.has_value();
    const std::array<Entry, 11> entries = {{
        {"summary", "Summary", true},
        {"assessment", "Assessment", true},
        {"findings", "Findings", true},
        {"headers", "Headers", hasPe},
        {"sections", "Sections", hasPe},
        {"imports", "Imports", hasPe},
        {"exports", "Exports", hasPe},
        {"directories", "Other structures", hasPe},
        {"indicators", "Indicators", true},
        {"entropy", "Entropy", result.entropy.has_value()},
        {"strings", "Strings", options.includeStrings && result.strings.has_value()},
    }};
    html.raw("<nav><ul>");
    for (const Entry& entry : entries) {
        if (!entry.shown) {
            continue;
        }
        html.raw("<li><a href=\"#");
        html.raw(entry.id);
        html.raw("\">");
        html.text(entry.title);
        html.raw("</a></li>");
    }
    html.raw("<li><a href=\"#enrichments\">Additional checks</a></li>"
             "<li><a href=\"#notes\">Analysis notes</a></li></ul></nav>\n");
}

void writeSummary(Html& html, const AnalysisResult& result, const ReportOptions& options) {
    html.raw("<section>");
    html.heading("Summary", "summary");
    html.beginFacts();
    html.fact("File", reportedFileName(result.file, options));
    html.fact("Size", byteSize(result.file.sizeBytes));
    html.fact("SHA-256", result.sha256);
    if (result.file.lastWriteTime) {
        html.fact("Last modified", formatUtc(*result.file.lastWriteTime));
    }
    html.fact("Identified as", result.identification.detail.empty()
                                   ? std::string(toString(result.identification.kind))
                                   : std::format("{} ({})", toString(result.identification.kind),
                                                 result.identification.detail));
    if (result.pe) {
        const PeImage& pe = *result.pe;
        const bool dll = (pe.coff.characteristics & pe::kFileDll) != 0;
        html.fact("Format", pe.format == PeFormat::Pe32Plus ? "PE32+ (64-bit)" : "PE32 (32-bit)");
        html.fact("Kind", dll ? "Dynamic-link library" : "Executable");
        html.fact("Architecture", std::format("{} ({})", pe::machineName(pe.coff.machine),
                                               hex(pe.coff.machine, 4)));
        html.fact("Subsystem", pe::subsystemName(pe.optional.subsystem));
        html.fact("Link timestamp", formatCoffTimestamp(pe.coff.timeDateStamp) +
                                         "; set by the linker, can be forged");
        html.fact("Entry point", "RVA " + hex(pe.optional.addressOfEntryPoint, 8));
        html.fact("Image base", hex(pe.optional.imageBase));
        html.fact("Sections", std::to_string(pe.sections.size()));
    }
    html.fact("Findings", std::to_string(result.findings.size()));
    html.endFacts();
    html.raw("</section>\n");
}

void writeAssessment(Html& html, const AnalysisResult& result) {
    const RiskAssessment& risk = result.risk;
    html.raw("<section>");
    html.heading("Assessment", "assessment");
    html.paragraph(risk.explanation, "prose");
    if (!risk.coverageGaps.empty()) {
        html.element("h3", "Not fully analyzed");
        html.paragraph("These parts of the analysis did not complete. Missing findings in them "
                       "do not mean nothing is there.");
        html.list(risk.coverageGaps);
    }
    if (!risk.contributions.empty()) {
        html.element("h3", "Score contributions");
        html.beginTable({{"Rule"}, {"Points", "num"}, {"Counted"}});
        for (const ScoreContribution& contribution : risk.contributions) {
            const std::string counted =
                contribution.counted ? std::string("yes")
                                     : "no; same behavior as " + contribution.correlatedWith;
            html.row({contribution.ruleId, std::format("{:.2f}", contribution.points), counted},
                     contribution.counted ? "" : "muted");
        }
        html.endTable();
    }
    html.raw("</section>\n");
}

void writeFinding(Html& html, const Finding& finding) {
    const std::string_view severity = reportToken(finding.severity);
    html.raw("<article class=\"finding severity-");
    html.raw(severity);
    html.raw("\"><header>");
    html.element("h3", finding.title);
    html.element("span", toString(finding.severity), std::format("badge severity-{}", severity));
    html.element("span", std::format("{} confidence", toString(finding.confidence)), "badge");
    html.element("code", finding.ruleId);
    html.raw("</header>");
    html.paragraph(finding.description, "prose");

    if (!finding.evidence.empty()) {
        html.element("h4", "Evidence");
        html.beginTable({{"Observation"}, {"Location"}, {"File offset", "num"}}, "evidence");
        for (const Evidence& evidence : finding.evidence) {
            html.row({evidence.description, evidence.location,
                      evidence.fileOffset ? hex(*evidence.fileOffset) : std::string("-")});
        }
        html.endTable();
    }
    if (!finding.explanation.empty()) {
        html.element("h4", "Why it matters");
        html.paragraph(finding.explanation, "prose");
    }
    if (!finding.limitations.empty()) {
        html.element("h4", "Limitations");
        html.paragraph(finding.limitations, "prose");
    }
    if (!finding.attack.empty()) {
        html.element("h4", "MITRE ATT&CK");
        std::vector<std::string> techniques;
        for (const AttackTechnique& technique : finding.attack) {
            techniques.push_back(std::format("{} {}", technique.id, technique.name));
        }
        html.list(techniques);
    }
    if (!finding.nextStep.empty()) {
        html.element("h4", "Suggested next step");
        html.paragraph(finding.nextStep, "prose");
    }
    html.raw("</article>\n");
}

void writeFindings(Html& html, const AnalysisResult& result) {
    html.raw("<section>");
    html.heading("Findings", "findings");
    if (result.findings.empty()) {
        html.paragraph("No detection rule reported a finding.");
    }
    // Most severe first; the stable sort keeps rule order within a severity.
    std::vector<const Finding*> ordered;
    for (const Finding& finding : result.findings) {
        ordered.push_back(&finding);
    }
    std::ranges::stable_sort(ordered, [](const Finding* a, const Finding* b) {
        return a->severity > b->severity;
    });
    for (const Finding* finding : ordered) {
        writeFinding(html, *finding);
    }
    html.raw("</section>\n");
}

void writeHeaders(Html& html, const PeImage& pe) {
    const CoffHeader& coff = pe.coff;
    const OptionalHeader& opt = pe.optional;
    const auto version = [](unsigned high, unsigned low) {
        return std::format("{}.{}", high, low);
    };

    html.raw("<section>");
    html.heading("Headers", "headers");
    html.raw("<div class=\"columns\"><div>");
    html.element("h3", "COFF file header");
    html.beginFacts();
    html.fact("Machine",
              std::format("{} ({})", pe::machineName(coff.machine), hex(coff.machine, 4)));
    html.fact("NumberOfSections", std::to_string(coff.numberOfSections));
    html.fact("TimeDateStamp", formatCoffTimestamp(coff.timeDateStamp));
    html.fact("PointerToSymbolTable", hex(coff.pointerToSymbolTable, 8));
    html.fact("NumberOfSymbols", std::to_string(coff.numberOfSymbols));
    html.fact("SizeOfOptionalHeader", hex(coff.sizeOfOptionalHeader, 4));
    html.fact("Characteristics",
              std::format("{} {}", hex(coff.characteristics, 4),
                          joined(pe::decodeFlags(coff.characteristics,
                                                 pe::coffCharacteristicFlags()))));
    html.endFacts();
    html.raw("</div><div>");
    html.element("h3", "Optional header");
    html.beginFacts();
    html.fact("Magic", std::format("{} ({})", hex(opt.magic, 4),
                                   pe.format == PeFormat::Pe32Plus ? "PE32+" : "PE32"));
    html.fact("LinkerVersion", version(opt.majorLinkerVersion, opt.minorLinkerVersion));
    html.fact("AddressOfEntryPoint", hex(opt.addressOfEntryPoint, 8));
    html.fact("ImageBase", hex(opt.imageBase, pe.format == PeFormat::Pe32Plus ? 16 : 8));
    html.fact("SectionAlignment", hex(opt.sectionAlignment));
    html.fact("FileAlignment", hex(opt.fileAlignment));
    html.fact("OperatingSystemVersion",
              version(opt.majorOperatingSystemVersion, opt.minorOperatingSystemVersion));
    html.fact("SubsystemVersion", version(opt.majorSubsystemVersion, opt.minorSubsystemVersion));
    html.fact("SizeOfImage", hex(opt.sizeOfImage));
    html.fact("SizeOfHeaders", hex(opt.sizeOfHeaders));
    html.fact("CheckSum", hex(opt.checksum, 8));
    html.fact("Subsystem", std::format("{} ({})", pe::subsystemName(opt.subsystem), opt.subsystem));
    html.fact("DllCharacteristics",
              std::format("{} {}", hex(opt.dllCharacteristics, 4),
                          joined(pe::decodeFlags(opt.dllCharacteristics,
                                                 pe::dllCharacteristicFlags()))));
    html.fact("SizeOfStackReserve", hex(opt.sizeOfStackReserve));
    html.fact("SizeOfHeapReserve", hex(opt.sizeOfHeapReserve));
    html.fact("NumberOfRvaAndSizes", std::to_string(opt.numberOfRvaAndSizes));
    html.endFacts();
    html.raw("</div></div>");

    html.element("h3", "Data directories");
    html.beginTable({{"#", "num"}, {"Directory"}, {"RVA", "num"}, {"Size", "num"}});
    for (const DataDirectory& directory : pe.dataDirectories) {
        html.row({std::to_string(directory.index), pe::dataDirectoryName(directory.index),
                  hex(directory.rva, 8), hex(directory.size, 8)},
                 directory.isEmpty() ? "muted" : "");
    }
    html.endTable();

    if (!pe.issues.empty()) {
        html.element("h3", "Structural issues");
        html.beginTable({{"Code"}, {"Description"}});
        for (const StructuralIssue& issue : pe.issues) {
            html.row({issue.code, issue.message});
        }
        html.endTable();
    }
    html.raw("</section>\n");
}

void writeSections(Html& html, const AnalysisResult& result) {
    const PeImage& pe = *result.pe;
    html.raw("<section>");
    html.heading("Sections", "sections");
    if (!pe.sectionTable.hasData()) {
        html.paragraph("Section table: " + statusText(pe.sectionTable));
    }
    if (!pe.sections.empty()) {
        html.beginTable({{"#", "num"},
                         {"Name"},
                         {"Virtual address", "num"},
                         {"Virtual size", "num"},
                         {"Raw offset", "num"},
                         {"Raw size", "num"},
                         {"Access"},
                         {"Raw data"},
                         {"Entropy", "num"},
                         {"Characteristics"}});
        for (std::size_t i = 0; i < pe.sections.size(); ++i) {
            const Section& section = pe.sections[i];
            const bool assessed = i < result.sections.sections.size();
            const bool measured = result.entropy && i < result.entropy->sections.size();
            html.row({std::to_string(i), section.name, hex(section.virtualAddress, 8),
                      hex(section.virtualSize), hex(section.pointerToRawData, 8),
                      hex(section.sizeOfRawData),
                      assessed ? permissionString(result.sections.sections[i].flags) : "-",
                      assessed ? toString(result.sections.sections[i].availability) : "-",
                      measured ? entropyText(result.entropy->sections[i]) : "-",
                      joined(describeSectionCharacteristics(section.characteristics))});
        }
        html.endTable();
    }

    const SectionAnalysis& analysis = result.sections;
    if (!analysis.anomalies.empty()) {
        html.element("h3", "Section anomalies");
        html.paragraph("Structural observations used by the detection rules. Legitimate software "
                       "shows some of them too.");
        html.beginTable({{"Kind"}, {"Section", "num"}, {"Description"}});
        for (const SectionAnomaly& anomaly : analysis.anomalies) {
            html.row({toString(anomaly.kind), std::to_string(anomaly.section),
                      anomaly.description});
        }
        html.endTable();
        if (analysis.anomaliesTruncated) {
            html.paragraph(std::format("Only the first {} anomalies were recorded.",
                                       SectionAnalysis::kMaxAnomalies),
                           "muted");
        }
    }
    html.raw("</section>\n");
}

void writeImports(Html& html, const ImportTable& imports) {
    html.raw("<section>");
    html.heading("Imports", "imports");
    html.beginFacts();
    html.fact("Import table", statusText(imports.status));
    html.fact("Delay-load table", statusText(imports.delayStatus));
    const std::size_t functionCount = std::accumulate(
        imports.modules.begin(), imports.modules.end(), std::size_t{0},
        [](std::size_t sum, const ImportedModule& entry) { return sum + entry.functions.size(); });
    html.fact("Total", std::format("{} functions from {} modules", functionCount,
                                   imports.modules.size()));
    html.endFacts();

    for (const ImportedModule& imported : imports.modules) {
        html.raw("<details><summary>");
        html.text(imported.name);
        html.raw(" <span class=\"muted\">");
        html.text(std::format("{} functions{}", imported.functions.size(),
                              imported.delayLoaded ? ", delay-loaded" : ""));
        html.raw("</span></summary>");
        html.beginTable({{"Function"}, {"Ordinal", "num"}, {"Hint", "num"}});
        for (const ImportedFunction& function : imported.functions) {
            html.row({function.name.empty() ? "(by ordinal)" : function.name,
                      function.ordinal ? std::to_string(*function.ordinal) : "-",
                      std::to_string(function.hint)});
        }
        html.endTable();
        html.raw("</details>\n");
    }
    html.raw("</section>\n");
}

void writeExports(Html& html, const ExportTable& exports) {
    html.raw("<section>");
    html.heading("Exports", "exports");
    html.beginFacts();
    html.fact("Export table", statusText(exports.status));
    if (exports.status.hasData()) {
        html.fact("DLL name", exports.dllName);
        html.fact("TimeDateStamp", formatCoffTimestamp(exports.timeDateStamp));
        html.fact("Ordinal base", std::to_string(exports.ordinalBase));
        html.fact("Functions", std::to_string(exports.functions.size()));
    }
    html.endFacts();
    if (!exports.functions.empty()) {
        html.raw("<details><summary>Exported functions</summary>");
        html.beginTable({{"Ordinal", "num"}, {"Name"}, {"RVA", "num"}, {"Forwarded to"}});
        for (const ExportedFunction& function : exports.functions) {
            html.row({std::to_string(function.ordinal),
                      function.name.empty() ? "(no name)" : function.name, hex(function.rva, 8),
                      function.forwarder.value_or("")});
        }
        html.endTable();
        html.raw("</details>");
    }
    html.raw("</section>\n");
}

std::string resourceKeyText(const ResourceEntry::Key& key) {
    if (!key.name.empty()) {
        return key.name;
    }
    return key.id ? std::to_string(*key.id) : std::string("-");
}

void writeDirectories(Html& html, const AnalysisResult& result) {
    const PeImage& pe = *result.pe;
    html.raw("<section>");
    html.heading("Other structures", "directories");

    html.element("h3", "Resources");
    html.beginFacts();
    html.fact("Resource directory", statusText(pe.resources.status));
    html.fact("Entries", std::to_string(pe.resources.entries.size()));
    html.endFacts();
    if (!pe.resources.entries.empty()) {
        html.raw("<details><summary>Resource entries</summary>");
        html.beginTable({{"Type"}, {"Name"}, {"Language"}, {"File offset", "num"},
                         {"Size", "num"}});
        for (const ResourceEntry& entry : pe.resources.entries) {
            html.row({resourceKeyText(entry.type), resourceKeyText(entry.name),
                      resourceKeyText(entry.language), hex(entry.fileOffset),
                      std::to_string(entry.size)});
        }
        html.endTable();
        html.raw("</details>");
    }

    html.element("h3", "Debug directory");
    html.beginFacts();
    html.fact("Status", statusText(pe.debug.status));
    for (const DebugEntry& entry : pe.debug.entries) {
        html.fact(pe::debugTypeName(entry.type),
                  entry.pdbPath ? *entry.pdbPath
                                : std::format("{} bytes at {}", entry.sizeOfData,
                                              hex(entry.pointerToRawData)));
    }
    html.endFacts();

    html.element("h3", "Thread-local storage");
    html.beginFacts();
    html.fact("Status", statusText(pe.tls.status));
    if (pe.tls.status.hasData()) {
        std::vector<std::string> callbacks;
        for (const std::uint64_t callback : pe.tls.callbacks) {
            callbacks.push_back(hex(callback));
        }
        html.fact("Callbacks", callbacks.empty() ? std::string("none") : joined(callbacks));
    }
    html.endFacts();

    html.element("h3", "Certificate table and overlay");
    html.beginFacts();
    html.fact("Certificate table", statusText(pe.certificate.status));
    if (pe.certificate.status.hasData()) {
        html.fact("Certificate location", std::format("{} bytes at {}", pe.certificate.size,
                                                      hex(pe.certificate.fileOffset)));
    }
    html.fact("Overlay", statusText(pe.overlay.status));
    if (pe.overlay.status.state == FieldState::Present) {
        html.fact("Overlay location",
                  std::format("{} at {}{}", byteSize(pe.overlay.size), hex(pe.overlay.fileOffset),
                              pe.overlay.containsCertificateTable
                                  ? "; contains the certificate table"
                                  : ""));
        if (result.entropy) {
            html.fact("Overlay entropy", entropyText(result.entropy->overlay));
        }
    }
    html.endFacts();
    html.raw("</section>\n");
}

void writeIndicators(Html& html, const AnalysisResult& result) {
    html.raw("<section>");
    html.heading("Indicators", "indicators");
    if (result.indicators.empty()) {
        html.paragraph(result.strings ? "No indicators were found in the extracted strings."
                                      : "Strings were not extracted, so no indicators are "
                                        "available.");
    } else {
        html.paragraph("Text found in the file that is worth a look. None of it means the file "
                       "does anything on its own.");
        html.beginTable({{"Kind"}, {"Value", "mono"}, {"File offset", "num"}});
        for (const Indicator& indicator : result.indicators) {
            html.row({toString(indicator.kind), indicator.value, hex(indicator.offset)});
        }
        html.endTable();
    }
    html.raw("</section>\n");
}

void writeEntropyChart(Html& html, const EntropyReport& report, std::uint64_t fileSize) {
    constexpr double kWidth = 1000.0;
    constexpr double kHeight = 160.0;
    if (report.profile.empty() || fileSize == 0) {
        return;
    }
    html.raw("<svg class=\"profile\" viewBox=\"0 0 1000 160\" preserveAspectRatio=\"none\" "
             "role=\"img\" aria-label=\"Entropy across the file\">");
    for (int bits = 2; bits < 8; bits += 2) {
        const double y = kHeight - (bits / kMaxEntropy) * kHeight;
        html.raw(std::format("<line class=\"grid\" x1=\"0\" x2=\"1000\" y1=\"{:.1f}\" "
                             "y2=\"{:.1f}\"/>",
                             y, y));
    }
    std::string points;
    const auto scale = kWidth / static_cast<double>(fileSize);
    for (const EntropyPoint& point : report.profile) {
        const double y = kHeight - std::clamp(point.entropy / kMaxEntropy, 0.0, 1.0) * kHeight;
        points += std::format("{:.1f},{:.1f} {:.1f},{:.1f} ",
                              static_cast<double>(point.offset) * scale, y,
                              static_cast<double>(point.offset + point.size) * scale, y);
    }
    html.raw("<polyline points=\"");
    html.raw(points);
    html.raw("\"/></svg>");
    html.paragraph(std::format("Entropy of consecutive {}-byte blocks from the start of the file "
                               "(left) to its end (right), on a scale of 0 to 8 bits per byte.",
                               report.profileBlockSize),
                   "muted");
}

void writeEntropy(Html& html, const AnalysisResult& result) {
    const EntropyReport& report = *result.entropy;
    html.raw("<section>");
    html.heading("Entropy", "entropy");
    html.beginFacts();
    html.fact("Whole file", report.file.total() > 0
                                ? std::format("{:.3f} bits per byte over {} bytes",
                                              report.file.entropy(), report.file.total())
                                : std::string("-"));
    html.fact("Distinct byte values", std::to_string(report.file.distinctValues()));
    html.endFacts();
    writeEntropyChart(html, report, result.file.sizeBytes);
    html.paragraph("High entropy suggests compressed or encrypted data. Compressed resources, "
                   "installers and signed files produce it legitimately.",
                   "muted");
    if (report.sectionBudgetExhausted) {
        html.paragraph("Some overlapping sections were not measured, to avoid reading the file "
                       "many times over.",
                       "muted");
    }
    html.raw("</section>\n");
}

void writeStrings(Html& html, const StringExtraction& extraction) {
    html.raw("<section>");
    html.heading("Strings", "strings");
    html.paragraph(std::format("{} strings{}.", extraction.strings.size(),
                               extraction.limitReached
                                   ? "; extraction stopped at the configured limit"
                                   : ""));
    html.raw("<details><summary>Extracted strings</summary>");
    html.beginTable({{"File offset", "num"}, {"Encoding"}, {"Text", "mono"}});
    for (const ExtractedString& string : extraction.strings) {
        html.row({hex(string.offset), toString(string.encoding),
                  string.truncated ? string.text + " [truncated]" : string.text});
    }
    html.endTable();
    html.raw("</details></section>\n");
}

void writeEnrichments(Html& html, const AnalysisResult& result) {
    html.raw("<section>");
    html.heading("Additional checks", "enrichments");
    if (result.enrichments.empty()) {
        html.paragraph("No optional checks were enabled for this analysis.");
    }
    for (const EnrichmentResult& enrichment : result.enrichments) {
        html.element("h3", enrichment.displayName);
        html.beginFacts();
        html.fact("Status", statusText(enrichment.status));
        if (!enrichment.version.empty()) {
            html.fact("Version", enrichment.version);
        }
        html.fact("Network", enrichment.usedNetwork ? "contacted a remote service"
                                                    : "not used");
        for (const EnrichmentProperty& property : enrichment.properties) {
            html.fact(property.name, property.value);
        }
        // The engine also lists these findings with all others, where they are shown in full.
        html.fact("Findings", std::to_string(enrichment.findings.size()));
        html.endFacts();
    }
    html.raw("</section>\n");
}

void writeNotes(Html& html, const AnalysisResult& result) {
    html.raw("<section>");
    html.heading("Analysis notes", "notes");
    if (result.warnings.empty() && result.skippedRules.empty() && result.failedRules.empty()) {
        html.paragraph("Every analysis stage and detection rule completed.");
    }
    if (!result.warnings.empty()) {
        html.element("h3", "Warnings");
        html.list(result.warnings);
    }
    const auto writeSkips = [&html](std::string_view title, const std::vector<RuleSkip>& skips) {
        if (skips.empty()) {
            return;
        }
        html.element("h3", title);
        html.beginTable({{"Rule"}, {"Reason"}});
        for (const RuleSkip& skip : skips) {
            html.row({skip.ruleId, skip.reason});
        }
        html.endTable();
    };
    writeSkips("Rules skipped", result.skippedRules);
    writeSkips("Rules that failed", result.failedRules);
    html.raw("</section>\n");
}

void writeFooter(Html& html, const AnalysisResult& result, const ReportOptions& options) {
    html.raw("<footer>");
    std::string text = std::format("Generated by Sectoryn {} using {} {}.", result.engine.version,
                                   result.engine.parserName, result.engine.parserVersion);
    if (options.includeRunTimes) {
        text += std::format(" Analysis started {} and finished {}.", formatUtc(result.run.started),
                            formatUtc(result.run.finished));
    }
    html.paragraph(text);
    html.raw("</footer>\n</body>\n</html>\n");
}

} // namespace

std::string renderHtmlReport(const AnalysisResult& result, const ReportOptions& options) {
    Html html;
    writeHead(html, result, options);
    html.raw("<main>\n");
    writeBanner(html, result, options);
    writeContents(html, result, options);
    writeSummary(html, result, options);
    writeAssessment(html, result);
    writeFindings(html, result);
    if (result.pe) {
        writeHeaders(html, *result.pe);
        writeSections(html, result);
        writeImports(html, result.pe->imports);
        writeExports(html, result.pe->exports);
        writeDirectories(html, result);
    }
    writeIndicators(html, result);
    if (result.entropy) {
        writeEntropy(html, result);
    }
    if (options.includeStrings && result.strings) {
        writeStrings(html, *result.strings);
    }
    writeEnrichments(html, result);
    writeNotes(html, result);
    html.raw("</main>\n");
    writeFooter(html, result, options);
    return html.take();
}

} // namespace sectoryn
