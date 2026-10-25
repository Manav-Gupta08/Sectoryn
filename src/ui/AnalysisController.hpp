#pragma once

#include "engine/AnalysisEngine.hpp"
#include "ui/AnalysisPanel.hpp"

#include <QObject>
#include <QString>

#include <memory>
#include <stop_token>
#include <thread>
#include <utility>

namespace sectoryn::ui {

// Runs one interactive analysis at a time on a worker thread and reports back on the UI thread.
// Destroying the controller cancels a running analysis and waits for the worker to finish, so no
// callback can outlive it.
class AnalysisController final : public QObject {
    Q_OBJECT

public:
    explicit AnalysisController(std::shared_ptr<const AnalysisEngine> engine,
                                QObject* parent = nullptr);
    ~AnalysisController() override;

    AnalysisController(const AnalysisController&) = delete;
    AnalysisController& operator=(const AnalysisController&) = delete;
    AnalysisController(AnalysisController&&) = delete;
    AnalysisController& operator=(AnalysisController&&) = delete;

    [[nodiscard]] bool isBusy() const noexcept { return busy_; }

    // Used from the next analysis on; one already running keeps the engine it started with.
    void setEngine(std::shared_ptr<const AnalysisEngine> engine) { engine_ = std::move(engine); }

public Q_SLOTS:
    // Returns false without doing anything while another analysis is running.
    bool analyze(const QString& path);
    void cancel();

Q_SIGNALS:
    void started(const QString& path);
    void progressed(sectoryn::AnalysisStage stage);
    void finished(const sectoryn::ui::SharedResult& result);
    void failed(const QString& path, const QString& message);
    void cancelled(const QString& path);

private:
    void deliver(const QString& path, Result<AnalysisResult> result);

    std::shared_ptr<const AnalysisEngine> engine_;
    std::jthread worker_;
    bool busy_ = false;
};

} // namespace sectoryn::ui
