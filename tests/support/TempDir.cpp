#include "support/TempDir.hpp"

#include <format>
#include <fstream>
#include <random>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace sectoryn::test {

TempDir::TempDir() {
    std::random_device entropy;
    std::mt19937_64 generator(entropy());
    const std::filesystem::path base = std::filesystem::temp_directory_path();

    for (int attempt = 0; attempt < 16; ++attempt) {
        std::filesystem::path candidate = base / std::format("sectoryn-test-{:016x}", generator());
        if (std::filesystem::create_directory(candidate)) {
            path_ = std::move(candidate);
            return;
        }
    }
    throw std::runtime_error("cannot create a unique temporary directory");
}

TempDir::~TempDir() {
    std::error_code ignored;
    std::filesystem::remove_all(path_, ignored);
}

std::filesystem::path TempDir::write(std::string_view name,
                                     std::span<const std::byte> contents) const {
    std::filesystem::path file = path_ / name;
    std::ofstream out(file, std::ios::out | std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(contents.data()),
              static_cast<std::streamsize>(contents.size()));
    if (!out) {
        throw std::runtime_error("cannot write temporary file");
    }
    return file;
}

std::filesystem::path TempDir::write(std::string_view name, std::string_view contents) const {
    return write(name, std::as_bytes(std::span(contents)));
}

} // namespace sectoryn::test
