#include "ui/Formatting.hpp"

#include <QDateTime>
#include <QLocale>
#include <QTimeZone>

namespace sectoryn::ui {

namespace {

// 2000-01-01 and 2100-01-01. Values outside are reproducible-build hashes or deliberate fakes.
constexpr std::uint32_t kPlausibleFrom = 946684800;
constexpr std::uint64_t kPlausibleUntil = 4102444800;

} // namespace

QString toQString(std::string_view text) {
    return QString::fromUtf8(text.data(), static_cast<qsizetype>(text.size()));
}

QString hex(std::uint64_t value, int digits) {
    return QStringLiteral("0x") +
           QString::number(value, 16).toUpper().rightJustified(digits, QLatin1Char('0'));
}

QString byteSize(std::uint64_t bytes) {
    const QString exact = QLocale::system().toString(static_cast<qulonglong>(bytes));
    if (bytes < 1024) {
        return QObject::tr("%1 bytes").arg(exact);
    }
    return QObject::tr("%1 (%2 bytes)")
        .arg(QLocale::system().formattedDataSize(static_cast<qint64>(bytes)), exact);
}

QString coffTimestamp(std::uint32_t seconds) {
    if (seconds == 0) {
        return QObject::tr("0 (not set)");
    }
    const QString raw = hex(seconds, 8);
    if (seconds < kPlausibleFrom || seconds >= kPlausibleUntil) {
        return QObject::tr("%1 (not a plausible date; possibly a reproducible-build hash)")
            .arg(raw);
    }
    const QDateTime time = QDateTime::fromSecsSinceEpoch(seconds, QTimeZone::utc());
    return QStringLiteral("%1 UTC (%2)")
        .arg(time.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")), raw);
}

QString fieldStatusText(const FieldStatus& status) {
    const QString state = toQString(toString(status.state));
    return status.detail.empty() ? state
                                 : QStringLiteral("%1: %2").arg(state, toQString(status.detail));
}

QString severityText(Severity severity) {
    switch (severity) {
    case Severity::Informational:
        return QObject::tr("Informational");
    case Severity::Low:
        return QObject::tr("Low");
    case Severity::Medium:
        return QObject::tr("Medium");
    case Severity::High:
        return QObject::tr("High");
    case Severity::Critical:
        return QObject::tr("Critical");
    }
    return QObject::tr("Unknown");
}

QString confidenceText(Confidence confidence) {
    switch (confidence) {
    case Confidence::Low:
        return QObject::tr("Low");
    case Confidence::Medium:
        return QObject::tr("Medium");
    case Confidence::High:
        return QObject::tr("High");
    }
    return QObject::tr("Unknown");
}

QColor severityColor(Severity severity) {
    switch (severity) {
    case Severity::Informational:
        return QColor(0x8a, 0x94, 0xa6);
    case Severity::Low:
        return QColor(0x5d, 0xa9, 0xe9);
    case Severity::Medium:
        return QColor(0xf0, 0xb4, 0x29);
    case Severity::High:
        return QColor(0xf2, 0x6d, 0x4f);
    case Severity::Critical:
        return QColor(0xe5, 0x39, 0x35);
    }
    return QColor(0x8a, 0x94, 0xa6);
}

} // namespace sectoryn::ui
