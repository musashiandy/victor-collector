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

**`victor run`'s daemon loop — current top priority.** Still just
prints a message (now enrollment-aware, but the loop itself doesn't
exist). What's missing: the heartbeat (~60s) and task-poll (~15s) async
loop, running the matching plugin when a task is polled, Privacy Mode
redaction, and the observation upload call. `sync_client.py` is where
this belongs — it already establishes the injectable-`httpx.Client`
pattern (`enroll()`'s `client` parameter) that `heartbeat()`/`tasks()`/
`upload_observations()` should reuse for the same dependency-free
testing `test_sync_client.py` already does via `httpx.MockTransport`.
Don't stub in fake success in the meantime — the current honest failure
is correct until this is actually built.

Privacy Mode redaction (`docs/collector-design.md` §8) is also not
built yet — there's been nothing to redact so far, since Standalone
Mode never uploads anything. It needs to land alongside `victor run`,
not after, since redaction has to be in place before the first real
upload, not bolted on retroactively.

`package-baseline-diff` (the one credentialed plugin) and the Docker
image are also still open — see `collector-design.md` §14.

## License

MIT. Keep it that way — see `KILLER_FEATURES.md` §4.9 in
victor-recon-console for why this repo is the open-source half of an
open-core split, not an oversight to "fix" later.
