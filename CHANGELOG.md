# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-28

First release.

### Analysis
- PE32 and PE32+ parsing through LIEF 0.17 behind a project-owned model, with independent
  validation of header, section and data directory ranges.
- DOS, COFF and optional headers, data directories, sections, imports (including delay imports
  and ordinals), exports (including forwarders), resources, debug and TLS directories,
  certificate table and overlay.
- Streaming SHA-256 through OpenSSL EVP.
- Shannon entropy for the file, each section, the overlay, and a profile across the file.
- ASCII and UTF-16LE string extraction with limits, and classification of URLs, domains, IPv4
  addresses, paths, registry keys and command fragments.

### Detection
- Explainable findings with separate severity and confidence, evidence with file offsets,
  limitations and next steps.
- Rules for header anomalies, section permissions and layout, entropy, suspicious API
  combinations (configurable catalogue), string indicators and certificate table layout.
- Risk score that counts each correlated behavior once and lists every contribution.
- Optional YARA scanning with libyara 4.3+.
- Authenticode verification on Windows.

### Application
- Qt 6 desktop workbench: overview, findings, headers, sections, imports, exports, resources,
  strings, entropy charts, signature, YARA, reputation and report panels.
- Analysis off the UI thread with progress and cancellation.
- Bounded batch analysis on a fixed worker pool with duplicate detection and batch export.
- JSON and self-contained HTML reports.
- Opt-in VirusTotal hash lookup with rate limiting and caching; the file is never uploaded.
- Settings for limits, workers, logging and the YARA rules folder; bounded analysis history.

### Quality
- Unit, integration, regression and UI test suites; fuzz harnesses; ASan/UBSan preset;
  clang-tidy and sanitizer CI jobs; benchmark harness.
- CPack packaging (NSIS and ZIP on Windows, DEB and tarball on Linux).

[0.1.0]: https://github.com/Manav-Gupta08/Sectoryn/releases/tag/v0.1.0
