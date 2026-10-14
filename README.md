# Sectoryn

Sectoryn is a native desktop workbench for static inspection and triage of Windows Portable
Executable (PE) files. It is written in C++20 with Qt 6 and is built to analyze suspicious
executables **without ever running them**.

> **Status:** early development. Only the build foundation exists so far. Features listed
> under *Planned* are not implemented yet.

## Goals

- Local-first analysis that works fully offline.
- Findings that explain their evidence and limitations instead of opaque verdicts.
- Hostile-input safety: every offset and size read from a file is validated.
- Bounded CPU, memory and disk usage.
- Analysis engine independent of the UI so it can be tested on its own.

Static analysis cannot prove that a file is malicious or safe. Sectoryn reports triage
outcomes, not classifications.

## Planned

- PE header, section, import, export, resource and overlay inspection
- SHA-256 hashing and entropy analysis
- String and indicator extraction
- Rule-based detection with explainable risk scoring
- HTML and JSON reports
- Bounded batch processing
- Optional YARA scanning, Authenticode verification and hash reputation lookups

## Building

### Requirements

| Tool         | Version                               |
| ------------ | ------------------------------------- |
| CMake        | 3.25 or newer                         |
| C++ compiler | GCC 13+, Clang 16+ or MSVC 19.36+     |
| Qt           | 6.4 or newer (Widgets)                |
| OpenSSL      | 3.0 or newer (libcrypto, for hashing) |
| nlohmann/json | 3.11 or newer                        |
| LIEF         | 0.17 (PE parsing; fetched if missing) |
| GoogleTest   | 1.11 or newer (tests only)            |
| Ninja        | any recent version                    |

If CMake cannot find an installed LIEF 0.17, the first configure downloads the pinned 0.17.6
release (checked against its SHA-256) and builds it with only the PE modules enabled. That first
build takes several minutes; later builds reuse it. To build offline, install LIEF 0.17 and
point `CMAKE_PREFIX_PATH` at it.

### Windows (MSYS2 UCRT64)

```sh
pacman -S --needed mingw-w64-ucrt-x86_64-{gcc,cmake,ninja,qt6-base,gtest,openssl,nlohmann-json}
cmake --preset msys2-debug
cmake --build --preset msys2-debug
ctest --preset msys2-debug
```

Make sure `C:\msys64\ucrt64\bin` is on `PATH` so the Qt and GoogleTest DLLs are found at run time.
If you configure with a CMake that is not MSYS2's own (for example one installed from cmake.org),
add `-DCMAKE_PREFIX_PATH=C:/msys64/ucrt64` to the first command so OpenSSL is found.

### Linux (Debian/Ubuntu)

```sh
sudo apt install build-essential cmake ninja-build qt6-base-dev libgl-dev libgtest-dev libssl-dev \
  nlohmann-json3-dev
cmake --preset linux-debug
cmake --build --preset linux-debug
ctest --preset linux-debug
```

The application binary is written to `build/<preset>/bin/`.

## Author

**Manav Gupta**

CyberSecurity Student | Software Developer | Backend Engineer

## License

Sectoryn is released under the [MIT License](LICENSE).
