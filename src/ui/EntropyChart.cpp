#include "ui/EntropyChart.hpp"

#include "analysis/Entropy.hpp"
#include "ui/Formatting.hpp"

#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QToolTip>

#include <algorithm>
#include <utility>

namespace sectoryn::ui {

namespace {

constexpr double kLeftMargin = 44;
constexpr double kRightMargin = 12;
constexpr double kTopMargin = 12;
constexpr double kBottomMargin = 36;
constexpr double kMaxBarWidth = 48;
constexpr double kBarFill = 0.7;

const QColor kAxis(0x5c, 0x63, 0x70);
const QColor kGrid(0x2c, 0x30, 0x36);
const QColor kText(0xae, 0xb5, 0xc0);
const QColor kNormal(0x4c, 0xc2, 0xd6);

} // namespace

EntropyChart::EntropyChart(QWidget* parent)
    : QWidget(parent) {
    setMouseTracking(true);
    setFocusPolicy(Qt::StrongFocus);
}

QSize EntropyChart::sizeHint() const {
    return {640, 220};
}

QSize EntropyChart::minimumSizeHint() const {
    return {240, 140};
}

void EntropyChart::setBars(std::vector<ChartBar> bars) {
    mode_ = Mode::Bars;
    bars_ = std::move(bars);
    points_.clear();
    QStringList summary;
    for (const ChartBar& bar : bars_) {
        summary.append(bar.value ? QStringLiteral("%1 %2").arg(bar.label).arg(*bar.value, 0, 'f', 2)
                                 : QStringLiteral("%1 n/a").arg(bar.label));
    }
    setAccessibleDescription(summary.join(QStringLiteral("; ")));
    update();
}

void EntropyChart::setProfile(std::vector<EntropyPoint> points, std::uint64_t fileSize) {
    mode_ = points.empty() ? Mode::Empty : Mode::Profile;
    points_ = std::move(points);
    bars_.clear();
    fileSize_ = fileSize;
    setAccessibleDescription(tr("Entropy across the file in %1 blocks").arg(points_.size()));
    update();
}

void EntropyChart::clear() {
    mode_ = Mode::Empty;
    bars_.clear();
    points_.clear();
    update();
}

QRectF EntropyChart::plotArea() const {
    return QRectF(kLeftMargin, kTopMargin, width() - kLeftMargin - kRightMargin,
                  height() - kTopMargin - kBottomMargin);
}

double EntropyChart::yFor(double entropy, const QRectF& plot) const {
    return plot.bottom() - std::clamp(entropy, 0.0, kMaxEntropy) / kMaxEntropy * plot.height();
}

int EntropyChart::itemAt(double x) const {
    const QRectF plot = plotArea();
    if (x < plot.left() || x > plot.right() || plot.width() <= 0) {
        return -1;
    }
    const double fraction = (x - plot.left()) / plot.width();
    if (mode_ == Mode::Bars && !bars_.empty()) {
        return std::min(static_cast<int>(fraction * static_cast<double>(bars_.size())),
                        static_cast<int>(bars_.size()) - 1);
    }
    if (mode_ == Mode::Profile && !points_.empty() && fileSize_ > 0) {
        const auto offset = static_cast<std::uint64_t>(fraction * static_cast<double>(fileSize_));
        const auto it = std::ranges::upper_bound(points_, offset, {}, &EntropyPoint::offset);
        return static_cast<int>(std::distance(points_.begin(), it)) - 1;
    }
    return -1;
}

void EntropyChart::paintEvent(QPaintEvent*) {
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    const QRectF plot = plotArea();
    if (plot.width() <= 0 || plot.height() <= 0) {
        return;
    }

    painter.setFont(font());
    for (int bits = 0; bits <= static_cast<int>(kMaxEntropy); bits += 2) {
        const double y = yFor(bits, plot);
        painter.setPen(bits == 0 ? kAxis : kGrid);
        painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y));
        painter.setPen(kText);
        painter.drawText(QRectF(0, y - 8, kLeftMargin - 6, 16), Qt::AlignRight | Qt::AlignVCenter,
                         QString::number(bits));
    }

    const QColor high = severityColor(Severity::Medium);
    if (threshold_ > 0.0) {
        const double thresholdY = yFor(threshold_, plot);
        painter.setPen(QPen(high, 1, Qt::DashLine));
        painter.drawLine(QPointF(plot.left(), thresholdY), QPointF(plot.right(), thresholdY));
    }

    if (mode_ == Mode::Empty) {
        painter.setPen(kText);
        painter.drawText(plot, Qt::AlignCenter, tr("No entropy data"));
        return;
    }

    if (mode_ == Mode::Bars) {
        const double slot = plot.width() / static_cast<double>(bars_.size());
        const double barWidth = std::min(kMaxBarWidth, slot * kBarFill);
        for (std::size_t i = 0; i < bars_.size(); ++i) {
            const ChartBar& bar = bars_[i];
            const double center = plot.left() + slot * (static_cast<double>(i) + 0.5);
            if (bar.value) {
                const double top = yFor(*bar.value, plot);
                painter.fillRect(QRectF(center - barWidth / 2, top, barWidth, plot.bottom() - top),
                                 threshold_ > 0.0 && *bar.value >= threshold_ ? high : kNormal);
            } else {
                painter.setPen(kText);
                painter.drawText(QRectF(center - slot / 2, plot.bottom() - 20, slot, 18),
                                 Qt::AlignCenter, tr("n/a"));
            }
            painter.setPen(kText);
            const QString label = fontMetrics().elidedText(bar.label, Qt::ElideRight,
                                                           static_cast<int>(slot) - 4);
            painter.drawText(QRectF(center - slot / 2, plot.bottom() + 4, slot, kBottomMargin - 6),
                             Qt::AlignHCenter | Qt::AlignTop, label);
        }
        return;
    }

    QPainterPath path;
    const auto scale = plot.width() / static_cast<double>(std::max<std::uint64_t>(fileSize_, 1));
    for (const EntropyPoint& point : points_) {
        const double x0 = plot.left() + static_cast<double>(point.offset) * scale;
        const double x1 = plot.left() + static_cast<double>(point.offset + point.size) * scale;
        const double y = yFor(point.entropy, plot);
        if (path.isEmpty()) {
            path.moveTo(x0, y);
        } else {
            path.lineTo(x0, y);
        }
        path.lineTo(x1, y);
    }
    painter.setPen(QPen(kNormal, 1.5));
    painter.drawPath(path);
    painter.setPen(kText);
    painter.drawText(QRectF(plot.left(), plot.bottom() + 4, plot.width(), kBottomMargin - 6),
                     Qt::AlignLeft | Qt::AlignTop, QStringLiteral("0x0"));
    painter.drawText(QRectF(plot.left(), plot.bottom() + 4, plot.width(), kBottomMargin - 6),
                     Qt::AlignRight | Qt::AlignTop, hex(fileSize_));
}

void EntropyChart::mouseMoveEvent(QMouseEvent* event) {
    const int index = itemAt(event->position().x());
    QString text;
    if (index >= 0 && mode_ == Mode::Bars) {
        text = bars_[static_cast<std::size_t>(index)].tooltip;
    } else if (index >= 0 && mode_ == Mode::Profile) {
        const EntropyPoint& point = points_[static_cast<std::size_t>(index)];
        text = tr("%1 - %2: %3 bits per byte")
                   .arg(hex(point.offset), hex(point.offset + point.size))
                   .arg(point.entropy, 0, 'f', 3);
    }
    if (text.isEmpty()) {
        QToolTip::hideText();
    } else {
        QToolTip::showText(event->globalPosition().toPoint(), text, this);
    }
}

} // namespace sectoryn::ui
