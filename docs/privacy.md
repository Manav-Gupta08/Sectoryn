# Privacy

Sectoryn works offline. Analysis, reports, YARA scanning and signature verification never use
the network.

## The one feature that does

The **Reputation** panel can look up a file's SHA-256 on VirusTotal. It is off unless you:

1. enter your own VirusTotal API key (kept in memory only, never written to disk), and
2. tick the consent box, which states what is sent and to whom, and
3. press **Look up** for that file.

What is sent: the SHA-256 of the file and your API key, over HTTPS to `www.virustotal.com`.
What is not sent: the file, its name or path, any other analysis result.

At most 4 lookups per minute are made, matching the public API quota, and a lookup that fails for
a transient reason is attempted at most 3 times. Answers are cached in memory for 24 hours (up to
256 hashes) so revisiting a file does not repeat the lookup.

Reputation results are shown separately and are labelled as external. They never change the
local findings or score, and they are not included in reports.

## Data stored on disk

| Data | Location | Contents |
|---|---|---|
| Settings | Qt's per-user config location, `sectoryn.conf` | Limits, worker count, log level, YARA folder |
| Log | Per-user data location, `logs/sectoryn.log`, capped at 1 MiB | Start/stop, errors |
| History | Per-user data location, `history.json`, bounded | SHA-256, file name (never the path), size, outcome, score, time of each analysis |

Tools → Clear Analysis History deletes the history. Reports are only written where you save
them; by default they contain the file name but not its full path.
