# victor-collector

Open-source recon agent for [VICTOR Recon](https://victorrecon.com) — runs
standalone with local AI, or connects to the cloud for deep AI triage. MIT
licensed.

> **Status: early v0.1.** `service-inventory` (port scan + banner grab) is
> real and end-to-end: run it, and it triages results against a local
> Ollama model and stores real findings. Everything else in the CLI
> (`enroll`, `run`, `ui`) exists as a real command but isn't implemented
> yet — see [Roadmap](#roadmap).

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

## Usage

```bash
# Scan a target you're authorized to test, triage locally against Ollama
victor recon service-inventory 10.10.10.25

# Skip triage, just see raw open ports/banners
victor recon service-inventory 10.10.10.25 --no-triage

# See what plugins exist
victor plugins list

# See locally stored findings (SQLite at ~/.victor/collector.db)
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

Tracked in the main repo's `docs/collector-design.md` §14 (MVP checklist).
Rough order: more recon plugins (TLS review, HTTP header audit, package
baseline diff) → `victor enroll`/`victor run` once the cloud API exists →
`victor ui` (local web dashboard) → Docker image.

## License

MIT — see [`LICENSE`](LICENSE).
