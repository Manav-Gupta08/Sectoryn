#include "ui/SignatureView.hpp"

#include "ui/Formatting.hpp"

#include <QHeaderView>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>

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

void field(QTreeWidgetItem* parent, const QString& name, const QString& value) {
    new QTreeWidgetItem(parent, {name, value});
}

void addCertificateTable(QTreeWidget* tree, const PeImage& pe) {
    QTreeWidgetItem* g = group(tree, QObject::tr("Certificate table"));
    field(g, QObject::tr("Status"), fieldStatusText(pe.certificate.status));
    if (pe.certificate.status.state == FieldState::Absent) {
        return;
    }
    field(g, QObject::tr("File offset"), hex(pe.certificate.fileOffset, 8));
    field(g, QObject::tr("Size"), byteSize(pe.certificate.size));
    field(g, QObject::tr("After the last section"),
          pe.overlay.containsCertificateTable ? QObject::tr("yes") : QObject::tr("no"));
}

void addVerification(QTreeWidget* tree, const AnalysisResult& result) {
    QTreeWidgetItem* g = group(tree, QObject::tr("Authenticode verification"));
    const EnrichmentResult* signature = findEnrichment(result, "signature");
    if (signature == nullptr) {
        field(g, QObject::tr("Status"),
              QObject::tr("Not performed. Verification uses Windows' WinVerifyTrust and is only "
                          "available in the Windows build."));
        return;
    }
    field(g, QObject::tr("Verifier"), toQString(signature->version));
    for (const EnrichmentProperty& property : signature->properties) {
        field(g, toQString(property.name), toQString(property.value));
    }
}

void addFindings(QTreeWidget* tree, const AnalysisResult& result) {
    QTreeWidgetItem* g = group(tree, QObject::tr("Signature findings"));
    bool any = false;
    for (const Finding& finding : result.findings) {
        if (!finding.ruleId.starts_with("signature.")) {
            continue;
        }
        any = true;
        auto* item =
            new QTreeWidgetItem(g, {toQString(finding.title), toQString(finding.description)});
        item->setForeground(0, severityColor(finding.severity));
    }
    if (!any) {
        field(g, QObject::tr("None"), QObject::tr("No signature-related findings."));
    }
}

} // namespace

const EnrichmentResult* findEnrichment(const AnalysisResult& result, std::string_view id) {
    const auto it = std::ranges::find(result.enrichments, id, &EnrichmentResult::id);
    return it == result.enrichments.end() ? nullptr : &*it;
}

SignatureView::SignatureView(QWidget* parent)
    : AnalysisPanel(parent)
    , tree_(new QTreeWidget(this)) {
    tree_->setColumnCount(2);
    tree_->setHeaderLabels({tr("Field"), tr("Value")});
    tree_->setAlternatingRowColors(true);
    tree_->setUniformRowHeights(true);
    tree_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tree_->setAccessibleName(tr("Signature details"));

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(tree_);
    setContent(content);
    clear();
}

void SignatureView::clear() {
    tree_->clear();
    showMessage(tr("Open a file to see its signature."));
}

void SignatureView::showResult(const SharedResult& result) {
    tree_->clear();
    if (!result->pe) {
        showMessage(tr("Signatures can only be inspected in PE files."));
        return;
    }
    addCertificateTable(tree_, *result->pe);
    addVerification(tree_, *result);
    addFindings(tree_, *result);
    tree_->expandAll();
    showContent();
}

} // namespace sectoryn::ui
