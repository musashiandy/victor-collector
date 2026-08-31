# Working in this repo

The design source of truth lives in the **victor-recon-console** repo,
not here: [`docs/collector-design.md`](https://github.com/musashiandy/victor-recon-console/blob/main/docs/collector-design.md)
is the buildable spec (CLI surface, plugin architecture, wire protocol,
data model, MVP checklist), [`docs/collector-architecture.md`](https://github.com/musashiandy/victor-recon-console/blob/main/docs/collector-architecture.md)
has the higher-level decisions and their reasoning. Check both before
changing behavior that contradicts them — if this repo and those docs
disagree, that's a bug in one of them, not a judgment call.

## Plugin pattern

Every plugin implements the `ReconPlugin` protocol
(`src/victor_collector/plugins/__init__.py`): `name`, `safe_mode`,
`requires_credentials`, and `run(target, config) -> list[RawObservation]`.
Register with `register(YourPlugin())` at module import time, then add
the import to `plugins/__init__.py`'s bottom-of-file import block —
**this step is easy to forget** (it happened once already; see the
git history of that file) and the failure mode is silent: the plugin
works fine in isolation and in its own tests, but the CLI can't find it
until you actually run `victor recon <plugin>` end-to-end. Always
smoke-test a new plugin through the real CLI, not just its unit tests.

Every plugin splits **execution** (real I/O — subprocess, socket, HTTP)
from **parsing/analysis** (pure functions) so the latter is unit-testable
without the real dependency:
- `service_inventory.py`: `parse_nmap_xml()` takes no subprocess
- `tls_review.py`: network probing is real, but `tests/conftest.py`'s
  `tls_test_server` fixture spins up a local self-signed TLS server so
  the test suite doesn't depend on an external target
- `http_header_audit.py`: `analyze_headers()` takes a constructed
  `httpx.Headers`, no network call

Follow this pattern for new plugins — it's what let `tls-review`'s
real bug (an exception-handling mistake in protocol probing) get caught
by a test instead of shipping silently.

## The open/closed line (don't blur this)

Local triage (`triage.py`) is deliberately simple: one observation in,
one `Finding` out, no cross-session correlation, no attack-chain
narrative. That's not a TODO — it's the actual boundary between what's
open source (this repo) and what VICTOR Recon's cloud sells (deep,
cross-session AI triage). See `collector-design.md` §1 and §9 before
"improving" triage to do more than that.

## CLI

`cli.py`'s `_run_recon()` is the shared execution loop every
`victor recon <plugin>` command calls through (run → save observation →
optional triage → save finding). Add a new recon command by writing a
thin wrapper plus a `_describe_<plugin>(raw: dict) -> str` one-line
summary formatter, not by duplicating the loop.

`victor ui`'s loopback-only bind check (`_LOOPBACK_HOSTS` in `cli.py`)
is a hard rule, not a default — it must keep refusing non-loopback
hosts even if someone passes `--host` explicitly. There's no auth in
v0.1; this is the only thing preventing findings from being exposed to
the network.

## Testing

```bash
pip install -e ".[dev]"
pytest
```

Every test should run without external dependencies (no live nmap, no
live target, no live Ollama) — that's why `conftest.py`'s TLS fixture
and the XML/header parsing splits exist. If a test needs something
external to pass, that's a sign the execution/parsing split wasn't
applied.

## Windows dev notes

- PowerShell's default execution policy blocks `.venv\Scripts\Activate.ps1`
  (and `npm.ps1`, unrelated but the same class of error). Call the venv's
  executables directly instead: `.venv\Scripts\victor.exe`,
  `.venv\Scripts\python.exe -m pytest`.
- No `.gitattributes` here yet, so git will warn about LF→CRLF on
  Windows checkouts. Harmless for a Python project — don't mass-fix by
  hand.

## What's not built yet

**`victor enroll` is real** — `sync_client.py` (the injectable-client
HTTP layer) and `credentials.py` (`~/.victor/credentials.json`, mode
`0600`) now do the actual token-exchange call against
`POST /v1/collectors/enroll`, verified against the real deployed API
(not just moto/mocks): a live Cognito user issued a real enrollment
token, `victor enroll` consumed it for a real credential, and replaying
the same token correctly got rejected. `status`, `run`, and
`collector-info` all read real enrollment state now instead of a
hardcoded "standalone" string.

**`victor run`'s daemon loop is real too now** — `daemon.py` polls
`GET /tasks`, heartbeats (immediately on picking up a task, every ~60s
while idle otherwise — `HEARTBEAT_INTERVAL_SECONDS`/
`POLL_INTERVAL_SECONDS`), runs the matching plugin via the existing
registry, redacts through `redaction.py`, and uploads via
`sync_client.upload_observations()`. `run_once()` is the single
poll/heartbeat/execute cycle, kept separate from `run_forever()`
specifically so it's testable without a real clock — see
`test_daemon.py`'s `httpx.MockTransport`-based tests, all synchronous
(no asyncio — see the module docstring for why that's a deliberate
deviation from `collector-design.md` §3's proposal).

Verified against real deployed AWS end to end, not just tests: enrolled
a real test collector, manually queued a real `Task` item in DynamoDB
(standing in for the still-missing task-creation endpoint —
`BACKLOG.md` M0.5), ran one real `run_once()` cycle, and confirmed in
DynamoDB that the task was marked completed and the observation landed
with `target` and the nested `raw.url` field both correctly redacted to
the same stable pseudonym. **Found and fixed a real production bug this
way**: the Lambda's IAM role never had `dynamodb:BatchWriteItem`, so
every real observation upload 500'd even though `POST /observations`
had been "complete" since M0 — moto's mocked tests never exercise real
IAM, so this was invisible until a real client with real credentials
hit it. Fixed via `iam put-role-policy` on
`victor-cloud-api-lambda-role`; see `DEPLOYMENT_STATUS.md` §2.

Privacy Mode redaction (`docs/collector-design.md` §8) is real —
`redaction.py`, stable per-session pseudonyms hashed with a per-session
salt stored in `~/.victor/redaction-map.db`, catching both the
observation's `target` field and any IPv4/exact-target-string matches
nested anywhere in `raw` (recursive walk over dicts/lists). Reversal
(for a future `report export` against cloud data) isn't built — nothing
needs it yet since nothing downstream of upload exists.

`package-baseline-diff` is real now too — the one credentialed plugin,
`plugins/package_baseline_diff.py`. SSHes in (`paramiko`), lists
packages (`dpkg -l`, falling back to `rpm -qa`), diffs against a
locally stored baseline established on the target's first run (never
overwritten automatically — a rolling diff against the previous run
would hide slow drift). Credential storage resolved §15's open
question: a plain file at `~/.victor/credentials/<name>.json`, mode
`0600`, populated by the operator — not an OS keyring, since `keyring`
needs a live Secret Service/D-Bus session that a headless Docker
container (this collector's only officially supported deployment
target) doesn't have by default. `parse_dpkg_output`/`parse_rpm_output`/
`diff_packages` are pure and fully tested; the real SSH call itself
isn't covered by an integration test (no local test server the way
`tls_review` has one — bootstrapping a real `sshd` is meaningfully
heavier, and neither Docker nor an SSH server was available in this
session's dev environment to stand one up). Verified for real anyway,
as far as this environment allows: the actual CLI, real credential
loading, and a real `paramiko` connection attempt against a genuinely
closed port all produce clean, correct errors end to end — only the
literal "parse a real server's real output" step is untested against a
live target.

The Docker image is the one thing still open from `collector-design.md`
§14's MVP checklist — see §11 for the base image and target platforms.

## License

MIT. Keep it that way — see `KILLER_FEATURES.md` §4.9 in
victor-recon-console for why this repo is the open-source half of an
open-core split, not an oversight to "fix" later.
