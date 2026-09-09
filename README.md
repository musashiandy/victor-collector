# victor-collector

Open-source recon agent for [VICTOR Recon](https://victorrecon.com) — runs
standalone with local AI, or connects to the cloud for deep AI triage. MIT
licensed.

> **Status: early v0.1.** All four MVP recon plugins (`service-inventory`,
> `tls-review`, `http-header-audit`, `package-baseline-diff`) are real:
> run one standalone, it triages results against a local Ollama model,
> stores real findings, and `victor ui` serves them in a local dashboard
> with HTML/Markdown/XLSX export — no cloud account needed. **The full
> cloud-connected loop is real too** — `victor enroll` and `victor run`
> (heartbeat, task poll, plugin execution, Privacy Mode redaction,
> observation upload) work against the live cloud API, verified
> end-to-end against real AWS including a real "Run Recon" click through
> the actual web UI queuing a task a real collector picked up organically
> (see `DEPLOYMENT_STATUS.md` in victor-recon-console). **The Docker
> image builds and passes CI** — verified by
> [GitHub Actions](https://github.com/musashiandy/victor-collector/actions/runs/34418102407)
> on a real Linux runner (Docker wasn't available in the dev environment
> that wrote the Dockerfile, so this was the first real build): all four
> plugins register correctly, `victor ui` refuses a non-loopback bind,
> `victor enroll` fails cleanly against an unreachable host, and an
> unenrolled `victor run` refuses to start. Publishing to
> `ghcr.io/musashiandy/victor-collector` happens on a version tag — no
> tag has been cut yet, so no image is published there today. See
> [Docker](#docker).

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

# Package baseline diff — needs a credential file first (the collector
# never generates or stores secrets for target hosts itself):
#   mkdir -p ~/.victor/credentials
#   echo '{"username":"svc","auth_method":"key","key_path":"/path/to/key"}' \
#     > ~/.victor/credentials/prod-host.json
victor recon package-baseline-diff 10.10.10.25 --credential-ref prod-host

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

## Docker

Docker is the officially supported deployment path
(`docs/collector-design.md` §10-§11). Two modes, matching whether you
pass a command:

```bash
# Cloud-connected: no command -> defaults to `victor run`. The
# entrypoint auto-enrolls on first boot using these env vars, so a
# fresh container just works without an operator running `victor
# enroll` by hand first.
docker run -d --name victor-collector \
  -e VICTOR_ENROLL_TOKEN=<one-time token from VICTOR Recon> \
  -e VICTOR_CONTROL_PLANE=https://api.victorrecon.com \
  -v victor-collector-data:/root/.victor \
  ghcr.io/musashiandy/victor-collector:latest

# Standalone: pass `victor ui` explicitly - no cloud, no token.
docker run -d --name victor-collector \
  -p 127.0.0.1:8787:8787 \
  -e VICTOR_OLLAMA_URL=http://host.docker.internal:11434 \
  -v victor-collector-data:/root/.victor \
  ghcr.io/musashiandy/victor-collector:latest victor ui
```

Any other command (`victor recon ...`, `victor findings`, etc.) also
passes straight through the entrypoint unmodified.

Images are built and smoke-tested by
[`.github/workflows/docker.yml`](.github/workflows/docker.yml) on every
push, and published to GHCR (`linux/amd64` + `linux/arm64`) only on a
version tag (`v*`) — not on every commit to `main`.

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
and `BACKLOG.md`'s M1. Every checklist item is done and CI-verified,
including the Docker image. What's left: cutting a real `v0.1.0` tag so
an image actually lands at `ghcr.io/musashiandy/victor-collector`
(nothing's published there yet, since publishing only happens on a
version tag); the two integration tests §14 originally scoped but this
pass didn't build (`service-inventory` against a docker-compose
Metasploitable-style fixture, and a full triage → SQLite → export
round-trip); and a security-model summary + `CONTRIBUTING.md` for the
README. PDF export (`weasyprint` in the original design) is deliberately
deferred
— it needs system-level Pango/Cairo libraries that complicate a clean
`pip install`; HTML/Markdown/XLSX cover the same need for now.

## License

MIT — see [`LICENSE`](LICENSE).
