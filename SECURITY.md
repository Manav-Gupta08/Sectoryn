# Security policy

## Supported versions

Only the latest release receives fixes.

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately through
GitHub's **Report a vulnerability** button on the repository's Security tab.

Include:

* the Sectoryn version and platform,
* what happens (crash, hang, unexpected output, anything leaving the machine),
* a minimal input that reproduces it. If the input is live malware, say so and share it only
  in a password-protected archive.

You will get an acknowledgement within a week. Fixes for crashes and memory errors in parsing
come with a regression test.

## Scope

In scope: anything that lets an analyzed file, a YARA rule file, a configuration file or a
reputation response crash Sectoryn, corrupt memory, exhaust resources beyond the configured
limits, inject content into reports or the UI, or cause data to be sent without consent.

See [docs/threat-model.md](docs/threat-model.md) for the trust boundaries.
