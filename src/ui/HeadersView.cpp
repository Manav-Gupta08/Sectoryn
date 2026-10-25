#include "ui/HeadersView.hpp"

#include "parsers/PeConstants.hpp"
#include "ui/Formatting.hpp"

#include <QHeaderView>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <cstdint>
#include <initializer_list>

namespace sectoryn::ui {

namespace {

QTreeWidgetItem* group(QTreeWidget* tree, const QString& name) {
    auto* item = new QTreeWidgetItem(tree, {name});
    QFont font = item->font(0);
    font.setBold(true);
    item->setFont(0, font);
    item->setFirstColumnSpanned(true);
    return item;
}

QTreeWidgetItem* field(QTreeWidgetItem* parent, const QString& name, const QString& value,
                       const QString& note = {}) {
    return new QTreeWidgetItem(parent, {name, value, note});
}

QString number(std::uint64_t value, int digits) {
    return QStringLiteral("%1 (%2)").arg(hex(value, digits)).arg(value);
}

QString flags(std::uint32_t value, std::span<const pe::FlagName> names) {
    QStringList decoded;
    for (const std::string& name : pe::decodeFlags(value, names)) {
        decoded.append(toQString(name));
    }
    return decoded.join(QStringLiteral(" | "));
}

void addDosHeader(QTreeWidget* tree, const DosHeader& dos) {
    QTreeWidgetItem* g = group(tree, QObject::tr("DOS header"));
    field(g, QStringLiteral("e_magic"), hex(dos.magic, 4),
          dos.magic == pe::kDosMagic ? QStringLiteral("MZ") : QObject::tr("not MZ"));
    field(g, QStringLiteral("e_cblp"), number(dos.bytesOnLastPage, 4));
    field(g, QStringLiteral("e_cp"), number(dos.pagesInFile, 4));
    field(g, QStringLiteral("e_crlc"), number(dos.relocations, 4));
    field(g, QStringLiteral("e_cparhdr"), number(dos.headerParagraphs, 4));
    field(g, QStringLiteral("e_minalloc"), number(dos.minExtraParagraphs, 4));
    field(g, QStringLiteral("e_maxalloc"), number(dos.maxExtraParagraphs, 4));
    field(g, QStringLiteral("e_ss"), hex(dos.initialSs, 4));
    field(g, QStringLiteral("e_sp"), hex(dos.initialSp, 4));
    field(g, QStringLiteral("e_csum"), hex(dos.checksum, 4));
    field(g, QStringLiteral("e_ip"), hex(dos.initialIp, 4));
    field(g, QStringLiteral("e_cs"), hex(dos.initialCs, 4));
    field(g, QStringLiteral("e_lfarlc"), hex(dos.relocationTableOffset, 4));
    field(g, QStringLiteral("e_ovno"), number(dos.overlayNumber, 4));
    field(g, QStringLiteral("e_oemid"), hex(dos.oemId, 4));
    field(g, QStringLiteral("e_oeminfo"), hex(dos.oemInfo, 4));
    field(g, QStringLiteral("e_lfanew"), hex(dos.peHeaderOffset, 8),
          QObject::tr("file offset of the PE signature"));
}

void addCoffHeader(QTreeWidget* tree, const CoffHeader& coff) {
    QTreeWidgetItem* g = group(tree, QObject::tr("COFF file header"));
    field(g, QStringLiteral("Machine"), hex(coff.machine, 4),
          toQString(pe::machineName(coff.machine)));
    field(g, QStringLiteral("NumberOfSections"), number(coff.numberOfSections, 4));
    field(g, QStringLiteral("TimeDateStamp"), hex(coff.timeDateStamp, 8),
          coffTimestamp(coff.timeDateStamp));
    field(g, QStringLiteral("PointerToSymbolTable"), hex(coff.pointerToSymbolTable, 8));
    field(g, QStringLiteral("NumberOfSymbols"), number(coff.numberOfSymbols, 8));
    field(g, QStringLiteral("SizeOfOptionalHeader"), number(coff.sizeOfOptionalHeader, 4));
    field(g, QStringLiteral("Characteristics"), hex(coff.characteristics, 4),
          flags(coff.characteristics, pe::coffCharacteristicFlags()));
}

void addOptionalHeader(QTreeWidget* tree, const PeImage& pe) {
    const OptionalHeader& o = pe.optional;
    QTreeWidgetItem* g = group(tree, QObject::tr("Optional header"));
    field(g, QStringLiteral("Magic"), hex(o.magic, 4),
          o.magic == pe::kPe32Magic       ? QStringLiteral("PE32")
          : o.magic == pe::kPe32PlusMagic ? QStringLiteral("PE32+")
                                          : QObject::tr("unknown; format inferred"));
    field(g, QStringLiteral("LinkerVersion"),
          QStringLiteral("%1.%2").arg(o.majorLinkerVersion).arg(o.minorLinkerVersion));
    field(g, QStringLiteral("SizeOfCode"), number(o.sizeOfCode, 8));
    field(g, QStringLiteral("SizeOfInitializedData"), number(o.sizeOfInitializedData, 8));
    field(g, QStringLiteral("SizeOfUninitializedData"), number(o.sizeOfUninitializedData, 8));
    field(g, QStringLiteral("AddressOfEntryPoint"), hex(o.addressOfEntryPoint, 8),
          QObject::tr("RVA"));
    field(g, QStringLiteral("BaseOfCode"), hex(o.baseOfCode, 8));
    if (o.baseOfData) {
        field(g, QStringLiteral("BaseOfData"), hex(*o.baseOfData, 8));
    }
    field(g, QStringLiteral("ImageBase"),
          hex(o.imageBase, pe.format == PeFormat::Pe32Plus ? 16 : 8));
    field(g, QStringLiteral("SectionAlignment"), number(o.sectionAlignment, 8));
    field(g, QStringLiteral("FileAlignment"), number(o.fileAlignment, 8));
    field(g, QStringLiteral("OperatingSystemVersion"),
          QStringLiteral("%1.%2").arg(o.majorOperatingSystemVersion).arg(
              o.minorOperatingSystemVersion));
    field(g, QStringLiteral("ImageVersion"),
          QStringLiteral("%1.%2").arg(o.majorImageVersion).arg(o.minorImageVersion));
    field(g, QStringLiteral("SubsystemVersion"),
          QStringLiteral("%1.%2").arg(o.majorSubsystemVersion).arg(o.minorSubsystemVersion));
    field(g, QStringLiteral("Win32VersionValue"), hex(o.win32VersionValue, 8));
    field(g, QStringLiteral("SizeOfImage"), number(o.sizeOfImage, 8));
    field(g, QStringLiteral("SizeOfHeaders"), number(o.sizeOfHeaders, 8));
    field(g, QStringLiteral("CheckSum"), hex(o.checksum, 8));
    field(g, QStringLiteral("Subsystem"), number(o.subsystem, 4),
          toQString(pe::subsystemName(o.subsystem)));
    field(g, QStringLiteral("DllCharacteristics"), hex(o.dllCharacteristics, 4),
          flags(o.dllCharacteristics, pe::dllCharacteristicFlags()));
    field(g, QStringLiteral("SizeOfStackReserve"), hex(o.sizeOfStackReserve));
    field(g, QStringLiteral("SizeOfStackCommit"), hex(o.sizeOfStackCommit));
    field(g, QStringLiteral("SizeOfHeapReserve"), hex(o.sizeOfHeapReserve));
    field(g, QStringLiteral("SizeOfHeapCommit"), hex(o.sizeOfHeapCommit));
    field(g, QStringLiteral("LoaderFlags"), hex(o.loaderFlags, 8));
    field(g, QStringLiteral("NumberOfRvaAndSizes"), number(o.numberOfRvaAndSizes, 8));
}

void addDataDirectories(QTreeWidget* tree, const PeImage& pe) {
    QTreeWidgetItem* g = group(tree, QObject::tr("Data directories"));
    for (std::uint32_t index = 0; index < pe::kDataDirectoryCount; ++index) {
        const QString name = QStringLiteral("%1  %2").arg(index, 2).arg(
            toQString(pe::dataDirectoryName(index)));
        const DataDirectory* entry = pe.declaredDirectory(index);
        if (entry == nullptr) {
            field(g, name, QStringLiteral("-"), fieldStatusText(pe.directoryAbsence(index)));
            continue;
        }
        const QString kind = index == pe::kCertificateDirectory ? QObject::tr("file offset")
                                                                : QObject::tr("RVA");
        field(g, name, QStringLiteral("%1 %2, size %3").arg(kind, hex(entry->rva, 8),
                                                           hex(entry->size, 8)));
    }
}

void addStructureStatus(QTreeWidget* tree, const PeImage& pe) {
    QTreeWidgetItem* g = group(tree, QObject::tr("Structures"));
    const std::initializer_list<std::pair<QString, const FieldStatus*>> structures = {
        {QObject::tr("Section table"), &pe.sectionTable},
        {QObject::tr("Imports"), &pe.imports.status},
        {QObject::tr("Delay imports"), &pe.imports.delayStatus},
        {QObject::tr("Exports"), &pe.exports.status},
        {QObject::tr("Resources"), &pe.resources.status},
        {QObject::tr("Debug directory"), &pe.debug.status},
        {QObject::tr("TLS directory"), &pe.tls.status},
        {QObject::tr("Certificate table"), &pe.certificate.status},
        {QObject::tr("Overlay"), &pe.overlay.status},
    };
    for (const auto& [name, status] : structures) {
        field(g, name, toQString(toString(status->state)), toQString(status->detail));
    }

    if (pe.tls.status.hasData()) {
        QTreeWidgetItem* tls = field(g, QObject::tr("TLS callbacks"),
                                     QString::number(pe.tls.callbacks.size()));
        for (const std::uint64_t callback : pe.tls.callbacks) {
            field(tls, QString(), hex(callback), QObject::tr("virtual address"));
        }
    }
    if (pe.debug.status.hasData()) {
        QTreeWidgetItem* debug = field(g, QObject::tr("Debug entries"),
                                       QString::number(pe.debug.entries.size()));
        for (const DebugEntry& entry : pe.debug.entries) {
            field(debug, toQString(pe::debugTypeName(entry.type)),
                  QObject::tr("%1 bytes at file offset %2")
                      .arg(entry.sizeOfData)
                      .arg(hex(entry.pointerToRawData, 8)),
                  entry.pdbPath ? toQString(*entry.pdbPath) : QString());
        }
    }
    if (pe.resources.status.hasData()) {
        field(g, QObject::tr("Resource entries"),
              QObject::tr("%1 data entries in %2 directories")
                  .arg(pe.resources.entries.size())
                  .arg(pe.resources.directoryCount));
    }
}

} // namespace

HeadersView::HeadersView(QWidget* parent)
    : AnalysisPanel(parent)
    , tree_(new QTreeWidget(this)) {
    tree_->setColumnCount(3);
    tree_->setHeaderLabels({tr("Field"), tr("Value"), tr("Notes")});
    tree_->setAlternatingRowColors(true);
    tree_->setUniformRowHeights(true);
    tree_->header()->setSectionResizeMode(QHeaderView::Interactive);
    tree_->setColumnWidth(0, 260);
    tree_->setColumnWidth(1, 220);
    tree_->setAccessibleName(tr("PE header fields"));
    setContent(tree_);
    clear();
}

void HeadersView::clear() {
    tree_->clear();
    issues_ = nullptr;
    showMessage(tr("Open a file to see its PE headers."));
}

void HeadersView::showResult(const SharedResult& result) {
    tree_->clear();
    issues_ = nullptr;
    if (!result->pe) {
        showMessage(tr("No PE headers are available.\n\n%1")
                        .arg(toQString(result->risk.explanation)));
        return;
    }
    const PeImage& pe = *result->pe;
    addDosHeader(tree_, pe.dos);
    addCoffHeader(tree_, pe.coff);
    addOptionalHeader(tree_, pe);
    addDataDirectories(tree_, pe);
    addStructureStatus(tree_, pe);

    issues_ = group(tree_, tr("Structural issues (%1)").arg(pe.issues.size()));
    for (const StructuralIssue& issue : pe.issues) {
        field(issues_, toQString(issue.code), QString(), toQString(issue.message));
    }

    tree_->expandAll();
    showContent();
}

bool HeadersView::reveal(const Evidence& evidence) {
    if (issues_ == nullptr || !evidence.location.starts_with("header.")) {
        return false;
    }
    const QString code = toQString(evidence.location);
    for (int i = 0; i < issues_->childCount(); ++i) {
        if (issues_->child(i)->text(0) == code) {
            tree_->setCurrentItem(issues_->child(i));
            tree_->scrollToItem(issues_->child(i));
            showContent();
            return true;
        }
    }
    return false;
}

} // namespace sectoryn::ui
