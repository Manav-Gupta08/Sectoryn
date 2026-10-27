# Architecture

Sectoryn is split into libraries with one direction of dependency. Everything below the user
interface is plain C++20 and can be used and tested without Qt.

```
            app (composition root)
             |
             ui  (Qt Widgets, Qt Network for the opt-in reputation lookup)
             |
  +----------+-----------+-----------+------------+
  reports    storage     engine      reputation
  |          |           |  \
  |          |           |   platform (Authenticode on Windows)
  +----------+-----------+
             |
          detectors ---- analysis ---- parsers ---- utilities ---- core
```

| Library | Responsibility |
|---|---|
| `core` | Error and result types, logging, limits, configuration, checked arithmetic, cancellation, bounded queue, worker pool |
| `utilities` | Bounded file reader, streaming SHA-256 (OpenSSL EVP), small atomic file writes |
| `parsers` | Project-owned PE model (`PeModel.hpp`) filled from LIEF, plus independent validation of every offset and size |
| `analysis` | File intake and identification, section analysis, entropy, string extraction, indicator classification |
| `detectors` | Finding model, rule interface and registry, built-in rules, risk scoring, optional YARA compiler and scanner |
| `engine` | `AnalysisEngine` runs one file end to end; `BatchManager` runs many on a fixed worker pool; optional enrichments (YARA, signature) |
| `platform` | Signature verification behind `ISignatureVerifier`; WinVerifyTrust on Windows, "unavailable" elsewhere |
| `reports` | JSON and HTML reports built from `AnalysisResult`, batch exports |
| `storage` | Bounded analysis history |
| `reputation` | Request building, response parsing, rate limiting and caching for hash lookups; performs no I/O itself |
| `ui` | Panels, models, controllers; consumes `AnalysisResult` and never parses files |
| `app` | Loads configuration, builds the engine and its optional modules, registers the panels |

## Data flow for one file

1. **Intake** – `openForAnalysis` checks the size limit and opens the file read-only.
2. **Hashing** – SHA-256 is streamed in `read_chunk_bytes` chunks.
3. **Identification** – magic bytes decide whether the file is PE; non-PE files end here with an
   explained "unsupported or invalid" outcome.
4. **Parsing** – the file is read once into memory (bounded by `max_file_bytes`), given to the
   parser, and released when the `PeImage` is built. `PeValidator` re-checks header ranges
   against the file size independently of LIEF.
5. **Sections, strings, entropy** – each works from the `PeImage` or streams the file again in
   chunks; none keeps a second copy of it.
6. **Enrichments** – optional modules (YARA, Authenticode) add properties and findings. Failures
   are recorded in the module's status rather than thrown.
7. **Rules and scoring** – rules see a read-only `RuleContext`; the scorer sums findings once per
   correlation group and records every input it used.

`AnalysisResult` is immutable once produced and shared with the UI and report writers through
`std::shared_ptr<const AnalysisResult>`.

## Threads

* The GUI thread never parses, hashes or scans. `AnalysisController` runs one interactive
  analysis on a `std::jthread`; `BatchManager` runs a fixed number of workers fed by a bounded
  queue. Results are posted back to the GUI thread with queued signals.
* Cancellation is cooperative (`std::stop_token`) and checked between chunks and stages. A
  cancelled job reports `Cancelled`, never a partial result marked as complete.
* The reputation lookup uses Qt's asynchronous network API on the GUI thread; it does not block.

## Error handling

Functions that can fail return `Result<T>` with an `ErrorCode` and message. Exceptions from
third-party code are caught at module boundaries (`AnalysisEngine::analyze`, enrichments) and
converted to errors. Structures that could not be read keep a `FieldStatus` explaining why, so a
missing table is never confused with an absent one.

## Extending

* **A rule** – implement `IRule`, register it in `createDefaultRules`, add tests in
  `tests/unit/test_rules.cpp`. Rules must be deterministic and explain their evidence.
* **An enrichment** – implement `IEnrichment`, construct it in `Application`. It must not throw
  for problems with the file or an external service.
* **A panel** – derive from `AnalysisPanel` and add it with `MainWindow::addPanel`.
