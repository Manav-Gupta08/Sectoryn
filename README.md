# Sectoryn

Sectoryn is a native desktop workbench for static inspection and triage of Windows Portable
Executable (PE) files. It is written in C++20 with Qt 6 and is built to analyze suspicious
executables **without ever running them**.

> **Status:** 0.1.0. Static PE analysis, detection, reporting and batch processing work on Linux
> and Windows. See [CHANGELOG.md](CHANGELOG.md) and [Known limitations](#known-limitations).

## Goals

- Local-first analysis that works fully offline.
- Findings that explain their evidence and limitations instead of opaque verdicts.
- Hostile-input safety: every offset and size read from a file is validated.
- Bounded CPU, memory and disk usage.
- Analysis engine independent of the UI so it can be tested on its own.

Static analysis cannot prove that a file is malicious or safe. Sectoryn reports triage
outcomes, not classifications.

## Features

- **PE inspection** - DOS, COFF and optional headers, data directories, sections with
  permissions and entropy, imports (delay-load and ordinals), exports (forwarders), resources,
  debug and TLS directories, certificate table and overlay. PE32 and PE32+.
- **File properties** - SHA-256 (OpenSSL), Shannon entropy for the file, sections, overlay and
  as a profile chart.
- **Strings and indicators** - ASCII and UTF-16LE strings with offsets; URLs, domains, IPv4
  addresses, paths, registry keys, command lines and encoded blobs flagged as *candidates*.
- **Explainable detection** - rules for header and section anomalies, packing signs, API
  combinations, string indicators and signature layout. Each finding has severity, confidence,
  evidence with file offsets, limitations and a next step. The risk score lists every input.
- **Reports** - reproducible JSON (documented schema) and self-contained HTML.
- **Batch analysis** - bounded worker pool and queue, per-file status, cancellation, duplicate
  detection, batch export.
- **Optional modules** - YARA scanning (libyara 4.3+), Authenticode verification (Windows),
  VirusTotal hash lookup (opt-in, hash only).

Nothing is ever executed: files are read as bytes, and nothing leaves the machine unless you
turn on the reputation lookup for a file.

## Documentation

| Topic | Document |
|---|---|
| How the code is organized | [docs/architecture.md](docs/architecture.md) |
| Trust boundaries and mitigations | [docs/threat-model.md](docs/threat-model.md) |
| Rules, severity, confidence and scoring | [docs/detection-methodology.md](docs/detection-methodology.md) |
| Entropy method | [docs/entropy.md](docs/entropy.md) |
| Report formats | [docs/report-format.md](docs/report-format.md) |
| Network use and stored data | [docs/privacy.md](docs/privacy.md) |
| Platforms | [docs/supported-platforms.md](docs/supported-platforms.md) |
| Tests, sanitizers, fuzzing | [docs/testing.md](docs/testing.md) |
| Performance | [docs/benchmarks.md](docs/benchmarks.md) |

## Building

### Requirements

| Tool         | Version                               |
| ------------ | ------------------------------------- |
| CMake        | 3.25 or newer                         |
| C++ compiler | GCC 13+, Clang 16+ or MSVC 19.36+     |
| Qt           | 6.4 or newer (Widgets, Network)       |
| OpenSSL      | 3.0 or newer (libcrypto, for hashing) |
| nlohmann/json | 3.11 or newer                        |
| LIEF         | 0.17 (PE parsing; fetched if missing) |
| libyara      | 4.3 or newer (optional)               |
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
  nlohmann-json3-dev libyara-dev
cmake --preset linux-debug
cmake --build --preset linux-debug
ctest --preset linux-debug
```

The application binary is written to `build/<preset>/bin/`. Without libyara, or with
`-DSECTORYN_WITH_YARA=OFF`, everything except YARA scanning is built.

Other presets: `linux-release`, `msys2-release`, and `linux-sanitize` (ASan + UBSan).
Packages: `cpack --config build/linux-release/CPackConfig.cmake`.

## Usage

```sh
sectoryn [file]
```

Open or drop a file on the dashboard. Analysis runs in the background and can be cancelled.
Tools → Batch Analysis (Ctrl+B) analyzes many files; Tools → Settings changes limits, worker
count, logging and the YARA rules folder (the `.yar`/`.yara` files directly in it are compiled
when the engine is built; the YARA panel shows any compile errors).
Reports are exported from the Report panel.

### Default limits

| Limit | Default |
|---|---|
| File size | 256 MiB |
| Sections | 96 |
| Imported modules / functions | 1,024 / 65,536 |
| Exports | 65,536 |
| Resource entries | 4,096 |
| Strings / string bytes | 100,000 / 16 MiB |
| String length | 5 to 4,096 characters |
| Batch workers / queued jobs | 2 / 256 |

A stage that reaches a limit says so, and the outcome becomes "analysis incomplete" unless
the findings already reach a threshold.

## Known limitations

- Static only: run-time behavior, unpacked code and decrypted payloads are not visible.
- .NET metadata is not interpreted beyond the PE container.
- Authenticode is verified only on Windows, against embedded signatures, with cached
  revocation data. Catalog-signed files appear unsigned.
- The risk score ranks files for attention. A low score does not mean a file is safe.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities as described in
[SECURITY.md](SECURITY.md).

## Author

**Manav Gupta**

CyberSecurity Student | Software Developer | Backend Engineer

## License

Sectoryn is released under the [MIT License](LICENSE).
