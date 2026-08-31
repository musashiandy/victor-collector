# victor-collector

Open-source recon agent for [VICTOR Recon](https://victorrecon.com) — runs
standalone with local AI, or connects to the cloud for deep AI triage. MIT
licensed.

> **Status: early v0.1.** Three recon plugins (`service-inventory`,
> `tls-review`, `http-header-audit`) are real end-to-end: run one, it
> triages results against a local Ollama model, stores real findings, and
> `victor ui` serves them in a local dashboard with HTML/Markdown/XLSX
> export — no cloud account needed. **The cloud API is now live in
> production** (see `DEPLOYMENT_STATUS.md` in victor-recon-console) —
> `enroll`/`run` exist as real CLI commands but still just print "not
> implemented"; the wire protocol they need to speak
> (`docs/collector-design.md` §7) has a real, proven server on the other
> end now, this client just hasn't been written yet. That's the current
> top priority — see [Roadmap](#roadmap).

## What this is

VICTOR Recon has two parts: the web dashboard (closed source) and this
collector (open source, MIT). The collector runs on your network, performs
recon, and either triages findings locally with your own AI (Standalone
Mode, no account needed) or uploads redacted observations to VICTOR Recon
for deeper, cross-session triage. Full design rationale is in
[`docs/collector-design.md`](https://github.com/musashiandy/victor-recon-console/blob/main/docs/collector-design.md)
and [`docs/collector-architecture.md`](https://github.com/musashiandy/victor-recon-console/blob/main/docs/collector-architecture.md)
in the main [victor-recon-console](https://github.com/musashiandy/victor-recon-console)
repo — that's the source of truth for where this is headed; this README
just covers what's actually built.

## Prerequisites

- Python 3.12+
- [nmap](https://nmap.org/download.html) on `PATH` — required for
  `service-inventory`. Never bundled (it's GPL-licensed; see
  `docs/collector-design.md` §5 for why this is invoked as a subprocess
  rather than vendored).
- [Ollama](https://ollama.com) running locally, if you want triage output
  rather than just raw scan results. Everything works without it —
  `--no-triage` skips straight to raw observations.

## Install

```bash
python -m venv .venv
source .venv/bin/activate   # .venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

> **Windows + PowerShell**: if your execution policy blocks `.ps1`
> scripts (`Activate.ps1` included), skip activation and call the venv's
> executables directly: `.venv\Scripts\victor.exe ui`,
> `.venv\Scripts\python.exe -m pytest`.

## Usage

```bash
# Scan a target you're authorized to test, triage locally against Ollama
victor recon service-inventory 10.10.10.25
victor recon tls-review 10.10.10.25
victor recon http-header-audit https://10.10.10.25

# Skip triage, just see raw scan results
victor recon service-inventory 10.10.10.25 --no-triage

# See what plugins exist
victor plugins list

# Browse findings in a local dashboard (http://127.0.0.1:8787, loopback-only)
victor ui

# Or just export without starting the dashboard
victor report-export --format html --output report.html
victor report-export --format xlsx --output report.xlsx

# Or list findings straight from the CLI
victor findings
```

Only run this against systems you own or have explicit written
authorization to test.

## Development

```bash
pip install -e ".[dev]"
pytest
```

`service_inventory.py` splits nmap execution from XML parsing on purpose
— `parse_nmap_xml()` has no subprocess dependency, so the test suite
doesn't require nmap installed.

## Roadmap

Tracked in the main repo's `docs/collector-design.md` §14 (MVP checklist)
and `BACKLOG.md`'s M1. Current priority order: real `victor enroll`/
`victor run` against the now-live cloud API (credential storage at
`~/.victor/credentials.json`, the heartbeat/poll/redact/upload daemon
loop) → Privacy Mode redaction (`docs/collector-design.md` §8 — not yet
built, since nothing has uploaded to the cloud yet to redact) →
`package-baseline-diff` (the one credentialed plugin) → Docker image.
PDF export (`weasyprint` in the original design) is deliberately deferred
— it needs system-level Pango/Cairo libraries that complicate a clean
`pip install`; HTML/Markdown/XLSX cover the same need for now.

## License

MIT — see [`LICENSE`](LICENSE).
