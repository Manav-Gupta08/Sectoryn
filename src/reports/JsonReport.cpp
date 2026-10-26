#include "reports/JsonReport.hpp"

#include "analysis/SectionCharacteristics.hpp"
#include "parsers/PeConstants.hpp"

#include <chrono>
#include <cstddef>
#include <format>
#include <optional>
#include <span>

namespace sectoryn {

namespace {

using Json = nlohmann::ordered_json;

template <typename T>
Json optionalValue(const std::optional<T>& value) {
    return value ? Json(*value) : Json(nullptr);
}

Json toJson(const FieldStatus& status) {
    Json json;
    json["state"] = reportToken(status.state);
    json["detail"] = status.detail;
    return json;
}

Json toJson(const Finding& finding) {
    Json evidence = Json::array();
    for (const Evidence& item : finding.evidence) {
        Json entry;
        entry["description"] = item.description;
        entry["location"] = item.location;
        entry["file_offset"] = optionalValue(item.fileOffset);
        evidence.push_back(std::move(entry));
    }
    Json attack = Json::array();
    for (const AttackTechnique& technique : finding.attack) {
        Json entry;
        entry["id"] = technique.id;
        entry["name"] = technique.name;
        attack.push_back(std::move(entry));
    }

    Json json;
    json["rule_id"] = finding.ruleId;
    json["title"] = finding.title;
    json["severity"] = reportToken(finding.severity);
    json["confidence"] = reportToken(finding.confidence);
    json["description"] = finding.description;
    json["evidence"] = std::move(evidence);
    json["explanation"] = finding.explanation;
    json["limitations"] = finding.limitations;
    json["attack"] = std::move(attack);
    json["next_step"] = finding.nextStep;
    json["correlation_group"] = finding.correlationGroup;
    return json;
}

Json toJson(const std::vector<Finding>& findings) {
    Json json = Json::array();
    for (const Finding& finding : findings) {
        json.push_back(toJson(finding));
    }
    return json;
}

Json toJson(const std::vector<RuleSkip>& skips) {
    Json json = Json::array();
    for (const RuleSkip& skip : skips) {
        Json entry;
        entry["rule_id"] = skip.ruleId;
        entry["reason"] = skip.reason;
        json.push_back(std::move(entry));
    }
    return json;
}

Json toJson(const RangeEntropy& range) {
    Json json;
    json["entropy"] = optionalValue(range.entropy);
    json["bytes"] = range.bytes;
    return json;
}

Json flagNames(std::uint32_t value, std::span<const pe::FlagName> flags) {
    return Json(pe::decodeFlags(value, flags));
}

Json dosHeader(const DosHeader& dos) {
    Json json;
    json["magic"] = dos.magic;
    json["bytes_on_last_page"] = dos.bytesOnLastPage;
    json["pages_in_file"] = dos.pagesInFile;
    json["relocations"] = dos.relocations;
    json["header_paragraphs"] = dos.headerParagraphs;
    json["min_extra_paragraphs"] = dos.minExtraParagraphs;
    json["max_extra_paragraphs"] = dos.maxExtraParagraphs;
    json["initial_ss"] = dos.initialSs;
    json["initial_sp"] = dos.initialSp;
    json["checksum"] = dos.checksum;
    json["initial_ip"] = dos.initialIp;
    json["initial_cs"] = dos.initialCs;
    json["relocation_table_offset"] = dos.relocationTableOffset;
    json["overlay_number"] = dos.overlayNumber;
    json["oem_id"] = dos.oemId;
    json["oem_info"] = dos.oemInfo;
    json["pe_header_offset"] = dos.peHeaderOffset;
    return json;
}

Json coffHeader(const CoffHeader& coff) {
    Json json;
    json["machine"] = coff.machine;
    json["machine_name"] = pe::machineName(coff.machine);
    json["number_of_sections"] = coff.numberOfSections;
    json["time_date_stamp"] = coff.timeDateStamp;
    json["pointer_to_symbol_table"] = coff.pointerToSymbolTable;
    json["number_of_symbols"] = coff.numberOfSymbols;
    json["size_of_optional_header"] = coff.sizeOfOptionalHeader;
    json["characteristics"] = coff.characteristics;
    json["characteristics_flags"] =
        flagNames(coff.characteristics, pe::coffCharacteristicFlags());
    return json;
}

Json optionalHeader(const OptionalHeader& header) {
    Json json;
    json["magic"] = header.magic;
    json["major_linker_version"] = header.majorLinkerVersion;
    json["minor_linker_version"] = header.minorLinkerVersion;
    json["size_of_code"] = header.sizeOfCode;
    json["size_of_initialized_data"] = header.sizeOfInitializedData;
    json["size_of_uninitialized_data"] = header.sizeOfUninitializedData;
    json["address_of_entry_point"] = header.addressOfEntryPoint;
    json["base_of_code"] = header.baseOfCode;
    json["base_of_data"] = optionalValue(header.baseOfData);
    json["image_base"] = header.imageBase;
    json["section_alignment"] = header.sectionAlignment;
    json["file_alignment"] = header.fileAlignment;
    json["major_operating_system_version"] = header.majorOperatingSystemVersion;
    json["minor_operating_system_version"] = header.minorOperatingSystemVersion;
    json["major_image_version"] = header.majorImageVersion;
    json["minor_image_version"] = header.minorImageVersion;
    json["major_subsystem_version"] = header.majorSubsystemVersion;
    json["minor_subsystem_version"] = header.minorSubsystemVersion;
    json["win32_version_value"] = header.win32VersionValue;
    json["size_of_image"] = header.sizeOfImage;
    json["size_of_headers"] = header.sizeOfHeaders;
    json["checksum"] = header.checksum;
    json["subsystem"] = header.subsystem;
    json["subsystem_name"] = pe::subsystemName(header.subsystem);
    json["dll_characteristics"] = header.dllCharacteristics;
    json["dll_characteristics_flags"] =
        flagNames(header.dllCharacteristics, pe::dllCharacteristicFlags());
    json["size_of_stack_reserve"] = header.sizeOfStackReserve;
    json["size_of_stack_commit"] = header.sizeOfStackCommit;
    json["size_of_heap_reserve"] = header.sizeOfHeapReserve;
    json["size_of_heap_commit"] = header.sizeOfHeapCommit;
    json["loader_flags"] = header.loaderFlags;
    json["number_of_rva_and_sizes"] = header.numberOfRvaAndSizes;
    return json;
}

Json dataDirectories(const std::vector<DataDirectory>& directories) {
    Json json = Json::array();
    for (const DataDirectory& directory : directories) {
        Json entry;
        entry["index"] = directory.index;
        entry["name"] = pe::dataDirectoryName(directory.index);
        entry["rva"] = directory.rva;
        entry["size"] = directory.size;
        json.push_back(std::move(entry));
    }
    return json;
}

std::string hexBytes(std::span<const std::uint8_t> bytes) {
    std::string text;
    text.reserve(bytes.size() * 2);
    for (const std::uint8_t byte : bytes) {
        text += std::format("{:02x}", byte);
    }
    return text;
}

Json sections(const AnalysisResult& result) {
    const PeImage& pe = *result.pe;
    Json json = Json::array();
    for (std::size_t i = 0; i < pe.sections.size(); ++i) {
        const Section& section = pe.sections[i];
        Json entry;
        entry["index"] = i;
        entry["name"] = section.name;
        entry["raw_name"] = hexBytes(section.rawName);
        entry["virtual_address"] = section.virtualAddress;
        entry["virtual_size"] = section.virtualSize;
        entry["pointer_to_raw_data"] = section.pointerToRawData;
        entry["size_of_raw_data"] = section.sizeOfRawData;
        entry["pointer_to_relocations"] = section.pointerToRelocations;
        entry["pointer_to_line_numbers"] = section.pointerToLineNumbers;
        entry["number_of_relocations"] = section.numberOfRelocations;
        entry["number_of_line_numbers"] = section.numberOfLineNumbers;
        entry["characteristics"] = section.characteristics;
        entry["characteristics_flags"] = describeSectionCharacteristics(section.characteristics);
        const bool assessed = i < result.sections.sections.size();
        entry["permissions"] =
            assessed ? Json(permissionString(result.sections.sections[i].flags)) : Json(nullptr);
        entry["raw_data"] = assessed
                                ? Json(reportToken(result.sections.sections[i].availability))
                                : Json(nullptr);
        entry["entropy"] = result.entropy && i < result.entropy->sections.size()
                               ? toJson(result.entropy->sections[i])
                               : Json(nullptr);
        json.push_back(std::move(entry));
    }
    return json;
}

Json sectionAnomalies(const SectionAnalysis& analysis) {
    Json items = Json::array();
    for (const SectionAnomaly& anomaly : analysis.anomalies) {
        Json entry;
        entry["kind"] = reportToken(anomaly.kind);
        entry["section"] = anomaly.section;
        entry["other_section"] = optionalValue(anomaly.otherSection);
        entry["description"] = anomaly.description;
        items.push_back(std::move(entry));
    }
    Json json;
    json["items"] = std::move(items);
    json["truncated"] = analysis.anomaliesTruncated;
    return json;
}

Json imports(const ImportTable& table) {
    Json modules = Json::array();
    for (const ImportedModule& imported : table.modules) {
        Json functions = Json::array();
        for (const ImportedFunction& function : imported.functions) {
            Json entry;
            entry["name"] = function.name;
            entry["ordinal"] = optionalValue(function.ordinal);
            entry["hint"] = function.hint;
            functions.push_back(std::move(entry));
        }
        Json entry;
        entry["name"] = imported.name;
        entry["delay_loaded"] = imported.delayLoaded;
        entry["functions"] = std::move(functions);
        modules.push_back(std::move(entry));
    }
    Json json;
    json["status"] = toJson(table.status);
    json["delay_status"] = toJson(table.delayStatus);
    json["modules"] = std::move(modules);
    return json;
}

Json exports(const ExportTable& table) {
    Json functions = Json::array();
    for (const ExportedFunction& function : table.functions) {
        Json entry;
        entry["name"] = function.name;
        entry["ordinal"] = function.ordinal;
        entry["rva"] = function.rva;
        entry["forwarder"] = optionalValue(function.forwarder);
        functions.push_back(std::move(entry));
    }
    Json json;
    json["status"] = toJson(table.status);
    json["dll_name"] = table.dllName;
    json["time_date_stamp"] = table.timeDateStamp;
    json["ordinal_base"] = table.ordinalBase;
    json["functions"] = std::move(functions);
    return json;
}

Json resourceKey(const ResourceEntry::Key& key) {
    Json json;
    json["id"] = optionalValue(key.id);
    json["name"] = key.name;
    return json;
}

Json resources(const ResourceTable& table) {
    Json entries = Json::array();
    for (const ResourceEntry& resource : table.entries) {
        Json entry;
        entry["type"] = resourceKey(resource.type);
        entry["name"] = resourceKey(resource.name);
        entry["language"] = resourceKey(resource.language);
        entry["file_offset"] = resource.fileOffset;
        entry["size"] = resource.size;
        entry["code_page"] = resource.codePage;
        entries.push_back(std::move(entry));
    }
    Json json;
    json["status"] = toJson(table.status);
    json["directory_count"] = table.directoryCount;
    json["entries"] = std::move(entries);
    return json;
}

Json debug(const DebugDirectory& directory) {
    Json entries = Json::array();
    for (const DebugEntry& debugEntry : directory.entries) {
        Json entry;
        entry["type"] = debugEntry.type;
        entry["type_name"] = pe::debugTypeName(debugEntry.type);
        entry["time_date_stamp"] = debugEntry.timeDateStamp;
        entry["size_of_data"] = debugEntry.sizeOfData;
        entry["address_of_raw_data"] = debugEntry.addressOfRawData;
        entry["pointer_to_raw_data"] = debugEntry.pointerToRawData;
        entry["pdb_path"] = optionalValue(debugEntry.pdbPath);
        entries.push_back(std::move(entry));
    }
    Json json;
    json["status"] = toJson(directory.status);
    json["entries"] = std::move(entries);
    return json;
}

Json tls(const TlsDirectory& directory) {
    Json json;
    json["status"] = toJson(directory.status);
    json["start_address_of_raw_data"] = directory.startAddressOfRawData;
    json["end_address_of_raw_data"] = directory.endAddressOfRawData;
    json["address_of_index"] = directory.addressOfIndex;
    json["address_of_callbacks"] = directory.addressOfCallbacks;
    json["size_of_zero_fill"] = directory.sizeOfZeroFill;
    json["characteristics"] = directory.characteristics;
    json["callbacks"] = directory.callbacks;
    return json;
}

Json peImage(const AnalysisResult& result) {
    const PeImage& pe = *result.pe;

    Json certificate;
    certificate["status"] = toJson(pe.certificate.status);
    certificate["file_offset"] = pe.certificate.fileOffset;
    certificate["size"] = pe.certificate.size;

    Json overlay;
    overlay["status"] = toJson(pe.overlay.status);
    overlay["file_offset"] = pe.overlay.fileOffset;
    overlay["size"] = pe.overlay.size;
    overlay["contains_certificate_table"] = pe.overlay.containsCertificateTable;
    overlay["entropy"] = result.entropy ? toJson(result.entropy->overlay) : Json(nullptr);

    Json issues = Json::array();
    for (const StructuralIssue& issue : pe.issues) {
        Json entry;
        entry["code"] = issue.code;
        entry["message"] = issue.message;
        issues.push_back(std::move(entry));
    }

    Json json;
    json["format"] = reportToken(pe.format);
    json["dos_header"] = dosHeader(pe.dos);
    json["coff_header"] = coffHeader(pe.coff);
    json["optional_header"] = optionalHeader(pe.optional);
    json["data_directories"] = dataDirectories(pe.dataDirectories);
    json["section_table"] = toJson(pe.sectionTable);
    json["sections"] = sections(result);
    json["section_anomalies"] = sectionAnomalies(result.sections);
    json["imports"] = imports(pe.imports);
    json["exports"] = exports(pe.exports);
    json["resources"] = resources(pe.resources);
    json["debug"] = debug(pe.debug);
    json["tls"] = tls(pe.tls);
    json["certificate"] = std::move(certificate);
    json["overlay"] = std::move(overlay);
    json["issues"] = std::move(issues);
    return json;
}

Json entropy(const EntropyReport& report) {
    Json file;
    file["entropy"] = report.file.total() > 0 ? Json(report.file.entropy()) : Json(nullptr);
    file["bytes"] = report.file.total();
    file["distinct_values"] = report.file.distinctValues();

    Json profile = Json::array();
    for (const EntropyPoint& point : report.profile) {
        Json entry;
        entry["offset"] = point.offset;
        entry["size"] = point.size;
        entry["entropy"] = point.entropy;
        profile.push_back(std::move(entry));
    }

    Json json;
    json["file"] = std::move(file);
    json["profile_block_size"] = report.profileBlockSize;
    json["profile"] = std::move(profile);
    json["section_budget_exhausted"] = report.sectionBudgetExhausted;
    return json;
}

Json strings(const StringExtraction& extraction, const ReportOptions& options) {
    Json json;
    json["count"] = extraction.strings.size();
    json["limit_reached"] = extraction.limitReached;
    if (options.includeStrings) {
        Json items = Json::array();
        for (const ExtractedString& string : extraction.strings) {
            Json entry;
            entry["offset"] = string.offset;
            entry["encoding"] = reportToken(string.encoding);
            entry["text"] = string.text;
            entry["truncated"] = string.truncated;
            items.push_back(std::move(entry));
        }
        json["items"] = std::move(items);
    }
    return json;
}

Json indicators(const std::vector<Indicator>& list) {
    Json json = Json::array();
    for (const Indicator& indicator : list) {
        Json entry;
        entry["kind"] = reportToken(indicator.kind);
        entry["value"] = indicator.value;
        entry["string_index"] = indicator.stringIndex;
        entry["offset"] = indicator.offset;
        json.push_back(std::move(entry));
    }
    return json;
}

Json enrichments(const std::vector<EnrichmentResult>& results) {
    Json json = Json::array();
    for (const EnrichmentResult& result : results) {
        Json properties = Json::array();
        for (const EnrichmentProperty& property : result.properties) {
            Json entry;
            entry["name"] = property.name;
            entry["value"] = property.value;
            properties.push_back(std::move(entry));
        }
        Json entry;
        entry["id"] = result.id;
        entry["name"] = result.displayName;
        entry["version"] = result.version;
        entry["status"] = toJson(result.status);
        entry["used_network"] = result.usedNetwork;
        entry["properties"] = std::move(properties);
        entry["findings"] = toJson(result.findings);
        json.push_back(std::move(entry));
    }
    return json;
}

Json assessment(const RiskAssessment& risk) {
    Json contributions = Json::array();
    for (const ScoreContribution& contribution : risk.contributions) {
        Json entry;
        entry["finding_index"] = contribution.findingIndex;
        entry["rule_id"] = contribution.ruleId;
        entry["points"] = contribution.points;
        entry["counted"] = contribution.counted;
        entry["correlated_with"] = contribution.correlatedWith;
        contributions.push_back(std::move(entry));
    }
    Json json;
    json["outcome"] = reportToken(risk.outcome);
    json["outcome_label"] = toString(risk.outcome);
    json["score"] = risk.score;
    json["max_score"] = RiskAssessment::kMaxScore;
    json["explanation"] = risk.explanation;
    json["coverage_gaps"] = risk.coverageGaps;
    json["contributions"] = std::move(contributions);
    return json;
}

} // namespace

nlohmann::ordered_json buildJsonReport(const AnalysisResult& result,
                                       const ReportOptions& options) {
    Json generator;
    generator["name"] = "Sectoryn";
    generator["version"] = result.engine.version;
    generator["parser"] = result.engine.parserName;
    generator["parser_version"] = result.engine.parserVersion;

    Json file;
    file["name"] = reportedFileName(result.file, options);
    file["size"] = result.file.sizeBytes;
    file["sha256"] = result.sha256;
    file["modified"] =
        result.file.lastWriteTime ? Json(formatUtc(*result.file.lastWriteTime)) : Json(nullptr);

    Json identification;
    identification["kind"] = reportToken(result.identification.kind);
    identification["detail"] = result.identification.detail;
    identification["pe_header_offset"] = optionalValue(result.identification.peHeaderOffset);

    Json rules;
    rules["skipped"] = toJson(result.skippedRules);
    rules["failed"] = toJson(result.failedRules);

    Json json;
    json["schema"] = "sectoryn-report";
    json["schema_version"] = kJsonReportSchemaVersion;
    json["generator"] = std::move(generator);
    if (options.includeRunTimes) {
        Json run;
        run["started"] = formatUtc(result.run.started);
        run["finished"] = formatUtc(result.run.finished);
        run["duration_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 result.run.finished - result.run.started)
                                 .count();
        json["run"] = std::move(run);
    }
    json["file"] = std::move(file);
    json["identification"] = std::move(identification);
    json["assessment"] = assessment(result.risk);
    json["findings"] = toJson(result.findings);
    json["rules"] = std::move(rules);
    json["warnings"] = result.warnings;
    json["pe"] = result.pe ? peImage(result) : Json(nullptr);
    json["entropy"] = result.entropy ? entropy(*result.entropy) : Json(nullptr);
    json["strings"] = result.strings ? strings(*result.strings, options) : Json(nullptr);
    json["indicators"] = indicators(result.indicators);
    json["enrichments"] = enrichments(result.enrichments);
    return json;
}

std::string renderJsonReport(const AnalysisResult& result, const ReportOptions& options) {
    std::string text = buildJsonReport(result, options)
                           .dump(2, ' ', false, nlohmann::ordered_json::error_handler_t::replace);
    text += '\n';
    return text;
}

} // namespace sectoryn
