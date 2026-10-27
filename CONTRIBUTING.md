# Contributing

Thanks for helping. Sectoryn opens hostile files, so correctness and safety come before
features.

## Ground rules

* Never execute, load or shell out to an analyzed file, and never add a feature that does.
* Treat every value read from a file as hostile. Use `CheckedMath.hpp` for offsets and sizes and
  check ranges before reading or allocating.
* Report failures and partial results; do not hide them or present them as complete.
* The analysis libraries must not depend on Qt. UI code consumes `AnalysisResult` only.
* Keep resource use bounded. New loops over file data need a limit in `AnalysisLimits`.
* Do not add sample malware to the repository. Build test inputs with `tests/support/PeBuilder`.

## Workflow

1. Open an issue first for anything larger than a small fix.
2. Build and run the tests:
   ```sh
   cmake --preset linux-debug -DSECTORYN_WARNINGS_AS_ERRORS=ON
   cmake --build --preset linux-debug
   ctest --preset linux-debug
   ```
3. For parser or analysis changes also run the sanitizer preset (`linux-sanitize`).
4. Format with `clang-format` (the repository's `.clang-format`) and keep clang-tidy clean.
5. Add tests with every change. Every fixed crash or wrong result gets a test in
   `tests/regression`.
6. Update the documentation the change affects (`README.md`, `docs/`).

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat(parsers): ...`,
`fix(reports): ...`, `test: ...`, `docs: ...`, `build: ...`, `ci: ...`, `perf: ...`. One logical
change per commit; each commit should build and pass the tests.

## Detection rules

A new rule needs a stable ID, a severity and a confidence chosen separately, evidence with
offsets where possible, limitations that name the common benign causes, and a next step. It
must be deterministic and must explain itself without the reader seeing the code. See
[docs/detection-methodology.md](docs/detection-methodology.md).

## Security issues

Please report them privately as described in [SECURITY.md](SECURITY.md).
