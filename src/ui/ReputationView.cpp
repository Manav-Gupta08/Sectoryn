#include "ui/ReputationView.hpp"

#include "reputation/VirusTotalProvider.hpp"
#include "ui/Formatting.hpp"

#include <QCheckBox>
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPushButton>
#include <QTimeZone>
#include <QTimer>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>

#include <chrono>
#include <optional>

namespace sectoryn::ui {

namespace {

constexpr std::size_t kCacheEntries = 256;
constexpr std::chrono::hours kCacheLifetime{24};
// The public VirusTotal API allows four lookups a minute.
constexpr std::size_t kRequestsPerWindow = 4;
constexpr std::chrono::seconds kRateWindow{60};
constexpr int kTimeoutMs = 20000;
constexpr const char* kTooLargeProperty = "sectorynResponseTooLarge";

std::optional<std::chrono::seconds> retryAfter(const QNetworkReply* reply) {
    bool ok = false;
    const qint64 seconds =
        QString::fromLatin1(reply->rawHeader("Retry-After")).trimmed().toLongLong(&ok);
    if (!ok || seconds < 0) {
        return std::nullopt;
    }
    return std::chrono::seconds{seconds};
}

QString utcTime(std::int64_t secondsSinceEpoch) {
    return QDateTime::fromSecsSinceEpoch(secondsSinceEpoch, QTimeZone::utc()).toString(Qt::ISODate);
}

void field(QTreeWidget* tree, const QString& name, const QString& value) {
    new QTreeWidgetItem(tree, {name, value});
}

} // namespace

ReputationView::ReputationView(QWidget* parent)
    : AnalysisPanel(parent)
    , disclosure_(new QLabel(this))
    , consent_(
          new QCheckBox(tr("Allow sending the SHA-256 of the current file to VirusTotal"), this))
    , apiKey_(new QLineEdit(this))
    , lookUp_(new QPushButton(tr("&Look Up Hash"), this))
    , state_(new QLabel(this))
    , report_(new QTreeWidget(this))
    , network_(new QNetworkAccessManager(this))
    , cache_(kCacheEntries, kCacheLifetime)
    , limiter_(kRequestsPerWindow, kRateWindow) {
    disclosure_->setTextFormat(Qt::PlainText);
    disclosure_->setWordWrap(true);
    disclosure_->setText(
        tr("%1\n\nThe API key is kept in memory only and is never written to disk. Lookups "
           "happen only when you press the button.")
            .arg(toQString(VirusTotalProvider({}).disclosure())));

    apiKey_->setEchoMode(QLineEdit::Password);
    apiKey_->setPlaceholderText(tr("VirusTotal API key"));
    apiKey_->setAccessibleName(tr("VirusTotal API key"));
    state_->setTextFormat(Qt::PlainText);
    state_->setWordWrap(true);
    state_->setTextInteractionFlags(Qt::TextSelectableByMouse);

    report_->setColumnCount(2);
    report_->setHeaderLabels({tr("Field"), tr("Value")});
    report_->setRootIsDecorated(false);
    report_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    report_->setAccessibleName(tr("Reputation report"));

    connect(consent_, &QCheckBox::toggled, this, &ReputationView::updateButton);
    connect(apiKey_, &QLineEdit::textChanged, this, &ReputationView::updateButton);
    connect(lookUp_, &QPushButton::clicked, this, &ReputationView::lookUp);

    auto* controls = new QHBoxLayout;
    controls->addWidget(apiKey_, 1);
    controls->addWidget(lookUp_);

    auto* content = new QWidget(this);
    auto* layout = new QVBoxLayout(content);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(disclosure_);
    layout->addWidget(consent_);
    layout->addLayout(controls);
    layout->addWidget(state_);
    layout->addWidget(report_, 1);
    setContent(content);
    clear();
}

ReputationView::~ReputationView() {
    abortPending();
}

void ReputationView::clear() {
    abortPending();
    result_.reset();
    report_->clear();
    updateButton();
    showMessage(tr("Open a file to look up its hash."));
}

void ReputationView::showResult(const SharedResult& result) {
    abortPending();
    result_ = result;
    report_->clear();
    updateButton();
    if (result_->sha256.empty()) {
        showMessage(tr("The file has no hash to look up."));
        return;
    }
    showContent();
    if (const std::optional<ReputationReport> cached =
            cache_.find("virustotal", result_->sha256, std::chrono::system_clock::now())) {
        showReport(*cached, true);
    } else {
        setState(tr("Not looked up. Nothing has been sent."));
    }
}

void ReputationView::lookUp() {
    if (!result_ || pending_ || !consent_->isChecked()) {
        return;
    }
    if (const std::optional<ReputationReport> cached =
            cache_.find("virustotal", result_->sha256, std::chrono::system_clock::now())) {
        showReport(*cached, true);
        return;
    }
    attempt_ = 0;
    pending_ = true;
    updateButton();
    send(generation_);
}

void ReputationView::send(std::uint64_t generation) {
    if (generation != generation_ || !result_) {
        return;
    }
    const VirusTotalProvider provider(apiKey_->text().trimmed().toStdString());
    const Result<HttpRequest> request = provider.buildRequest(result_->sha256);
    if (!request) {
        pending_ = false;
        setState(toQString(request.error().describe()));
        updateButton();
        return;
    }

    const auto wait = limiter_.delayBeforeNext(std::chrono::steady_clock::now());
    if (wait.count() > 0) {
        setState(tr("Waiting %1 s for the VirusTotal rate limit.")
                     .arg(std::chrono::ceil<std::chrono::seconds>(wait).count()));
        QTimer::singleShot(wait, this, [this, generation] { send(generation); });
        return;
    }

    QNetworkRequest network(QUrl(QString::fromStdString(request.value().url)));
    for (const auto& [name, value] : request.value().headers) {
        network.setRawHeader(QByteArray::fromStdString(name), QByteArray::fromStdString(value));
    }
    network.setTransferTimeout(kTimeoutMs);

    ++attempt_;
    limiter_.record(std::chrono::steady_clock::now());
    QNetworkReply* reply = network_->get(network);
    reply_ = reply;
    connect(reply, &QNetworkReply::downloadProgress, reply, [reply](qint64 received, qint64) {
        if (received > static_cast<qint64>(VirusTotalProvider::kMaxResponseBytes)) {
            reply->setProperty(kTooLargeProperty, true);
            reply->abort();
        }
    });
    connect(reply, &QNetworkReply::finished, this,
            [this, reply, generation] { finished(reply, generation); });
    setState(tr("Looking up the hash on VirusTotal (attempt %1 of %2)...")
                 .arg(attempt_)
                 .arg(retry_.maxAttempts));
}

void ReputationView::finished(QNetworkReply* reply, std::uint64_t generation) {
    reply->deleteLater();
    if (reply_ == reply) {
        reply_ = nullptr;
    }
    if (generation != generation_ || !result_) {
        return;
    }
    if (reply->property(kTooLargeProperty).toBool()) {
        pending_ = false;
        setState(tr("The VirusTotal response was too large and was discarded."));
        updateButton();
        return;
    }

    HttpResponse response;
    const QVariant status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    response.status = status.isValid() ? status.toInt() : 0;
    response.body = reply->readAll().toStdString();
    response.retryAfter = retryAfter(reply);

    if (const auto delay = retry_.nextDelay(attempt_, response)) {
        setState(tr("The lookup failed (%1); retrying in %2 s.")
                     .arg(response.status == 0 ? reply->errorString()
                                               : tr("HTTP %1").arg(response.status))
                     .arg(std::chrono::ceil<std::chrono::seconds>(*delay).count()));
        QTimer::singleShot(*delay, this, [this, generation] { send(generation); });
        return;
    }

    pending_ = false;
    updateButton();
    const Result<ReputationReport> report =
        VirusTotalProvider({}).parseResponse(result_->sha256, response);
    if (!report) {
        QString message = toQString(report.error().describe());
        if (response.status == 0) {
            message += QStringLiteral(" (%1)").arg(reply->errorString());
        }
        setState(message);
        return;
    }
    cache_.store(report.value());
    showReport(report.value(), false);
}

void ReputationView::showReport(const ReputationReport& report, bool fromCache) {
    report_->clear();
    field(report_, tr("Source"), tr("VirusTotal (external service)"));
    if (report.known) {
        field(report_, tr("Malicious"), QString::number(report.malicious));
        field(report_, tr("Suspicious"), QString::number(report.suspicious));
        field(report_, tr("Harmless"), QString::number(report.harmless));
        field(report_, tr("Undetected"), QString::number(report.undetected));
        field(report_, tr("Last analysis"),
              report.lastAnalysis ? utcTime(*report.lastAnalysis) : tr("unknown"));
    } else {
        field(report_, tr("Record"), tr("VirusTotal has no record of this hash."));
    }
    field(report_, tr("Web page"), toQString(report.permalink));
    const auto retrieved =
        std::chrono::duration_cast<std::chrono::seconds>(report.retrievedAt.time_since_epoch())
            .count();
    field(report_, tr("Retrieved"),
          fromCache ? tr("%1 (cached)").arg(utcTime(retrieved)) : utcTime(retrieved));
    setState(tr("External information. It is not part of Sectoryn's findings or risk score, "
                "and counts of engines are not a verdict."));
}

void ReputationView::setState(const QString& text) {
    state_->setText(text);
}

void ReputationView::abortPending() {
    ++generation_;
    pending_ = false;
    attempt_ = 0;
    if (QNetworkReply* reply = reply_.data(); reply != nullptr) {
        reply->abort();
    }
}

void ReputationView::updateButton() {
    lookUp_->setEnabled(result_ && !result_->sha256.empty() && consent_->isChecked() &&
                        !apiKey_->text().trimmed().isEmpty() && !pending_);
}

} // namespace sectoryn::ui
