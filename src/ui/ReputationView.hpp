#pragma once

#include "reputation/RateLimiter.hpp"
#include "reputation/ReputationCache.hpp"
#include "ui/AnalysisPanel.hpp"

#include <QPointer>

#include <cstdint>

class QCheckBox;
class QLabel;
class QLineEdit;
class QNetworkAccessManager;
class QNetworkReply;
class QPushButton;
class QTreeWidget;

namespace sectoryn::ui {

// Optional hash lookup on VirusTotal. Nothing is sent until the user has read what will be sent,
// agreed to it, entered an API key and pressed the button; the key is kept in memory only.
// The answer is shown here alone and never changes the local findings or score.
class ReputationView final : public AnalysisPanel {
    Q_OBJECT

public:
    explicit ReputationView(QWidget* parent = nullptr);
    ~ReputationView() override;

    ReputationView(const ReputationView&) = delete;
    ReputationView& operator=(const ReputationView&) = delete;
    ReputationView(ReputationView&&) = delete;
    ReputationView& operator=(ReputationView&&) = delete;

    [[nodiscard]] QString title() const override { return tr("Reputation"); }
    void showResult(const SharedResult& result) override;
    void clear() override;

public Q_SLOTS:
    void lookUp();

private:
    void send(std::uint64_t generation);
    void finished(QNetworkReply* reply, std::uint64_t generation);
    void showReport(const ReputationReport& report, bool fromCache);
    void setState(const QString& text);
    void abortPending();
    void updateButton();

    QLabel* disclosure_;
    QCheckBox* consent_;
    QLineEdit* apiKey_;
    QPushButton* lookUp_;
    QLabel* state_;
    QTreeWidget* report_;
    QNetworkAccessManager* network_;
    QPointer<QNetworkReply> reply_;

    SharedResult result_;
    ReputationCache cache_;
    RateLimiter limiter_;
    RetryPolicy retry_;
    int attempt_ = 0;
    // A lookup is waiting for the rate limit, a retry or a reply.
    bool pending_ = false;
    // Incremented whenever the file changes, so late replies and timers for an old file are
    // ignored.
    std::uint64_t generation_ = 0;
};

} // namespace sectoryn::ui
