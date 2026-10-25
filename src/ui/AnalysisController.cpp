#include "ui/AnalysisController.hpp"

#include <QMetaObject>

#include <filesystem>
#include <utility>

namespace sectoryn::ui {

AnalysisController::AnalysisController(std::shared_ptr<const AnalysisEngine> engine,
                                       QObject* parent)
    : QObject(parent)
    , engine_(std::move(engine)) {}

AnalysisController::~AnalysisController() {
    // The worker only posts queued calls to this object, so joining here cannot deadlock; any
    // call still queued is discarded by Qt together with the object.
    worker_.request_stop();
    if (worker_.joinable()) {
        worker_.join();
    }
}

bool AnalysisController::analyze(const QString& path) {
    if (busy_) {
        return false;
    }
    busy_ = true;
    Q_EMIT started(path);

    worker_ = std::jthread([this, engine = engine_, path](const std::stop_token& token) {
        const std::filesystem::path file(path.toStdU16String());
        Result<AnalysisResult> result =
            engine->analyze(file, token, [this, &token](AnalysisStage stage) {
                if (!token.stop_requested()) {
                    QMetaObject::invokeMethod(
                        this, [this, stage] { Q_EMIT progressed(stage); }, Qt::QueuedConnection);
                }
            });
        QMetaObject::invokeMethod(
            this,
            [this, path, outcome = std::make_shared<Result<AnalysisResult>>(std::move(result))] {
                deliver(path, std::move(*outcome));
            },
            Qt::QueuedConnection);
    });
    return true;
}

void AnalysisController::cancel() {
    worker_.request_stop();
}

void AnalysisController::deliver(const QString& path, Result<AnalysisResult> result) {
    busy_ = false;
    if (result) {
        Q_EMIT finished(std::make_shared<const AnalysisResult>(std::move(result).value()));
    } else if (result.error().code == ErrorCode::Cancelled) {
        Q_EMIT cancelled(path);
    } else {
        Q_EMIT failed(path, QString::fromStdString(result.error().describe()));
    }
}

} // namespace sectoryn::ui
