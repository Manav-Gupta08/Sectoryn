#pragma once

#include <cstddef>
#include <filesystem>
#include <span>
#include <string_view>

namespace sectoryn::test {

// Creates a unique directory under the system temp directory and removes it on destruction.
class TempDir {
public:
    TempDir();
    ~TempDir();

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    TempDir(TempDir&&) = delete;
    TempDir& operator=(TempDir&&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const noexcept { return path_; }

    std::filesystem::path write(std::string_view name, std::span<const std::byte> contents) const;
    std::filesystem::path write(std::string_view name, std::string_view contents) const;

private:
    std::filesystem::path path_;
};

} // namespace sectoryn::test
