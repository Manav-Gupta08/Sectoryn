# Third-party notices

Sectoryn uses the components below. Versions are the ones pinned or tested by the build; licenses
were checked against each project's own license file.

## Linked into Sectoryn

| Component | Version | License | Use |
|---|---|---|---|
| [LIEF](https://github.com/lief-project/LIEF) | 0.17.6 | Apache-2.0 | PE parsing |
| [Qt](https://www.qt.io/) | 6.4 or newer | LGPL-3.0-only | Desktop interface (dynamically linked) |
| [OpenSSL](https://www.openssl.org/) | 3.0 or newer | Apache-2.0 | SHA-256 (libcrypto) |
| [nlohmann/json](https://github.com/nlohmann/json) | 3.11 or newer | MIT | Rule catalogues and JSON reports |

When LIEF is built from source, it compiles the following bundled components into the LIEF library:

| Component | Version | License |
|---|---|---|
| [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) | 3.6.4 | Apache-2.0 OR GPL-2.0-or-later (used under Apache-2.0) |
| [spdlog](https://github.com/gabime/spdlog) (includes {fmt}) | 1.15.3 | MIT |
| [frozen](https://github.com/serge-sans-paille/frozen) | f6dbec6 | Apache-2.0 |
| [tl::expected](https://github.com/TartanLlama/expected) | 1.2.0 | CC0-1.0 |
| [tcb/span](https://github.com/tcbrindle/span) | b70b0ff | BSL-1.0 |
| [utfcpp](https://github.com/nemtrif/utfcpp) | 4.0.6 | BSL-1.0 |

## Build and test only

| Component | Version | License |
|---|---|---|
| [GoogleTest](https://github.com/google/googletest) | 1.11 or newer | BSD-3-Clause |
| [CMake](https://cmake.org/) | 3.25 or newer | BSD-3-Clause |

Distributions of Sectoryn must include the license texts of the linked components. Qt is used
under the LGPL; binary packages ship Qt as shared libraries so it can be replaced by the user.
