#include "analysis/EntropyAnalyzer.hpp"
#include "analysis/SectionAnalyzer.hpp"
#include "analysis/StringExtractor.hpp"
#include "engine/AnalysisEngine.hpp"
#include "engine/BatchManager.hpp"
#include "parsers/LiefPeParser.hpp"
#include "support/PeBuilder.hpp"
#include "support/TempDir.hpp"
#include "utilities/FileReader.hpp"
#include "utilities/Sha256.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <functional>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/resource.h>
#endif

// Times each analysis stage on synthetic PE files and prints a Markdown table. Usage:
//   sectoryn_bench [repetitions]
namespace sectoryn {
namespace {

using Clock = std::chrono::steady_clock;

// Deterministic content: half pseudo-random bytes, half printable text with embedded strings.
std::vector<std::byte> syntheticPe(std::size_t bytes) {
    std::vector<std::byte> code(0x4000);
    std::uint64_t state = 0x9E3779B97F4A7C15ULL;
    for (std::byte& b : code) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        b = static_cast<std::byte>(state >> 56U);
    }
    std::vector<std::byte> file =
        test::PeBuilder(PeFormat::Pe32Plus)
            .addSection(".text", test::PeBuilder::kCode, code)
            .addSection(".rdata", test::PeBuilder::kReadOnly,
                        test::bytesOf("http://example.org/update\0C:\\Windows\\Temp\\x.dat\0"))
            .addImport("KERNEL32.dll", {"CreateFileW", "ReadFile", "VirtualAlloc"})
            .build();
    const std::string text = "Software\\Example\\Settings value=12345 ";
    while (file.size() < bytes) {
        for (int i = 0; i < 64 && file.size() < bytes; ++i) {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            file.push_back(static_cast<std::byte>(state >> 56U));
        }
        for (const char c : text) {
            if (file.size() >= bytes) {
                break;
            }
            file.push_back(static_cast<std::byte>(c));
        }
    }
    return file;
}

struct Timing {
    double median = 0;
    double best = 0;
};

Timing measure(int repetitions, const std::function<void()>& body) {
    std::vector<double> samples;
    for (int i = 0; i < repetitions; ++i) {
        const auto start = Clock::now();
        body();
        samples.push_back(std::chrono::duration<double, std::milli>(Clock::now() - start).count());
    }
    if (samples.empty()) {
        return {};
    }
    std::ranges::sort(samples);
    return {samples[samples.size() / 2], samples[0]};
}

template <typename T>
T require(Result<T> result, std::string_view what) {
    if (!result) {
        std::cerr << what << " failed: " << result.error().describe() << '\n';
        std::exit(1); // NOLINT(concurrency-mt-unsafe): no other threads are running here
    }
    return std::move(result).value();
}

void row(std::string_view stage, std::size_t bytes, const Timing& timing) {
    const double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
    std::cout << std::format("| {} | {:.0f} MiB | {:.1f} | {:.1f} | {:.0f} |\n", stage, mib,
                             timing.median, timing.best, mib / (timing.median / 1000.0));
}

void benchmarkFile(const test::TempDir& dir, std::size_t bytes, int repetitions) {
    const std::vector<std::byte> data = syntheticPe(bytes);
    const std::filesystem::path path = dir.write(std::format("bench-{}.exe", bytes), data);
    const AnalysisLimits limits;

    row("SHA-256", bytes, measure(repetitions, [&] {
            FileReader reader = require(FileReader::open(path), "open");
            static_cast<void>(require(sha256File(reader, limits.readChunkBytes, {}), "hash"));
        }));

    const LiefPeParser parser;
    PeImage image;
    row("PE parsing", bytes, measure(repetitions, [&] {
            image = require(parser.parse(data, limits, {}), "parse");
        }));

    const SectionAnalysis sections = analyzeSections(image);
    row("Entropy", bytes, measure(repetitions, [&] {
            FileReader reader = require(FileReader::open(path), "open");
            static_cast<void>(
                require(analyzeEntropy(reader, sections, image.overlay, limits, {}), "entropy"));
        }));

    row("Strings", bytes, measure(repetitions, [&] {
            FileReader reader = require(FileReader::open(path), "open");
            static_cast<void>(require(extractStrings(reader, limits, {}), "strings"));
        }));

    const AnalysisEngine engine = require(AnalysisEngine::createDefault(), "engine");
    row("Full analysis", bytes, measure(repetitions, [&] {
            static_cast<void>(require(engine.analyze(path), "analysis"));
        }));
}

void benchmarkBatch(const test::TempDir& dir, std::size_t files, std::size_t bytes) {
    std::vector<std::filesystem::path> paths;
    for (std::size_t i = 0; i < files; ++i) {
        std::vector<std::byte> data = syntheticPe(bytes);
        // Distinct content so no file is skipped as a duplicate.
        data.push_back(static_cast<std::byte>(i & 0xFFU));
        data.push_back(static_cast<std::byte>(i >> 8U));
        paths.push_back(dir.write(std::format("batch-{}.exe", i), data));
    }
    auto engine =
        std::make_shared<const AnalysisEngine>(require(AnalysisEngine::createDefault(), "engine"));

    std::cout << "\n| Workers | Files | Wall time (ms) | Files/s |\n|---|---|---|---|\n";
    for (const std::size_t workers : {1U, 2U, 4U}) {
        if (workers > std::max(1U, std::thread::hardware_concurrency())) {
            break;
        }
        const auto start = Clock::now();
        {
            auto batch = require(
                BatchManager::create(engine, {workers, files}, [](const JobUpdate&) {}), "batch");
            for (const auto& path : paths) {
                static_cast<void>(require(batch->submit(path), "submit"));
            }
            batch->waitForIdle();
        }
        const double ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        std::cout << std::format("| {} | {} | {:.0f} | {:.1f} |\n", workers, files, ms,
                                 static_cast<double>(files) / (ms / 1000.0));
    }
}

void printPeakMemory() {
#if defined(__unix__) || defined(__APPLE__)
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#if defined(__APPLE__)
        const double mib = static_cast<double>(usage.ru_maxrss) / (1024.0 * 1024.0);
#else
        const double mib = static_cast<double>(usage.ru_maxrss) / 1024.0;
#endif
        std::cout << std::format("\nPeak resident memory of the whole run: {:.0f} MiB\n", mib);
    }
#else
    std::cout << "\nPeak memory is not measured on this platform.\n";
#endif
}

} // namespace
} // namespace sectoryn

int main(int argc, char* argv[]) {
    using namespace sectoryn;
    const int repetitions = argc > 1 ? std::max(1, std::atoi(argv[1])) : 5;
    const test::TempDir dir;

    std::cout << std::format("Repetitions per measurement: {}\n\n", repetitions);
    std::cout << "| Stage | Input | Median (ms) | Best (ms) | MiB/s (median) |\n"
                 "|---|---|---|---|---|\n";
    for (const std::size_t mib : {1U, 16U, 64U}) {
        benchmarkFile(dir, mib * 1024U * 1024U, repetitions);
    }
    benchmarkBatch(dir, 32, 4U * 1024U * 1024U);
    printPeakMemory();
    return 0;
}
