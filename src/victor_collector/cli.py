"""CLI surface - matches docs/collector-design.md §4 in victor-recon-console.

`victor recon <plugin> <target>` is real end to end right now: run the
plugin, save the observation, triage it locally against Ollama if
reachable, save and print the resulting finding. `enroll` is now real
too - see sync_client.py and credentials.py. `run`'s heartbeat/poll/
upload loop is still not implemented; the local web UI is a separate
build step (victor_collector.ui).
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import typer

from victor_collector import credentials, daemon, export, plugins, policy, storage, sync_client, triage
from victor_collector.models import Target
from victor_collector.plugins import PluginConfig

app = typer.Typer(name="victor", help="VICTOR Collector - open-source recon agent.")
recon_app = typer.Typer(help="Run a single recon plugin against a target.")
plugins_app = typer.Typer(help="Inspect available recon plugins.")
app.add_typer(recon_app, name="recon")
app.add_typer(plugins_app, name="plugins")


@app.command()
def enroll(
    token: str = typer.Option(..., "--token", help="One-time enrollment token from VICTOR Recon."),
    control_plane: str = typer.Option(..., "--control-plane", help="Cloud API base URL."),
) -> None:
    """Exchange a one-time token for a long-lived collector credential."""
    try:
        creds = sync_client.enroll(token, control_plane)
    except sync_client.EnrollmentError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from None

    credentials.save(creds)
    typer.secho(f"Enrolled as {creds.collector_id}.", fg=typer.colors.GREEN)
    typer.echo(f"Credential stored at {credentials.CREDENTIALS_PATH} (mode 0600).")
    typer.echo("Authorize targets locally with `victor authorize`, then run `victor run`.")


@app.command(name="authorize")
def authorize_target(
    target: str,
    expires: str = typer.Option(..., "--expires", help="Authorization expiry with timezone, e.g. 2026-11-01T00:00:00Z."),
    allowed_plugins: str = typer.Option("service-inventory,tls-review,http-header-audit", "--plugins", help="Comma-separated plugin names."),
) -> None:
    """Record independent operator approval for cloud tasks on this exact target."""
    names = [name.strip() for name in allowed_plugins.split(",") if name.strip()]
    try:
        for name in names:
            plugins.get(name)
        policy.authorize(target, expires, names)
    except (ValueError, policy.PolicyError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from None
    typer.echo(f"Local authorization stored at {policy.POLICY_PATH}. No cloud task can expand it.")


@app.command()
def status() -> None:
    """Show collector enrollment status."""
    creds = credentials.load()
    if creds is None:
        typer.echo("Standalone - not enrolled with any control plane.")
        return
    typer.echo(f"Enrolled as {creds.collector_id} @ {creds.control_plane}")
    typer.echo(f"Enrolled at: {creds.enrolled_at.isoformat()}")


@app.command(name="run")
def run_daemon() -> None:
    """Cloud-connected daemon mode: heartbeat + task poll loop."""
    creds = credentials.load()
    if creds is None:
        typer.secho(
            "Not enrolled. Run `victor enroll --token <token> --control-plane <url>` first.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=1)

    typer.echo(f"Enrolled as {creds.collector_id} @ {creds.control_plane}")
    try:
        daemon.run_forever(creds, on_event=typer.echo)
    except KeyboardInterrupt:
        typer.echo("\nStopped.")
    except sync_client.SyncError as exc:
        typer.secho(f"Fatal sync error: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from None


_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


@app.command()
def ui(
    port: int = typer.Option(8787, help="Local dashboard port."),
    host: str = typer.Option(
        "127.0.0.1",
        help="Bind address. Refuses anything non-loopback - see docs/collector-design.md section 9.",
    ),
) -> None:
    """Standalone Mode local web UI (Findings + Export, no cloud account needed)."""
    if host not in _LOOPBACK_HOSTS:
        typer.secho(
            f"Refusing to bind to '{host}' - victor ui only serves loopback "
            f"(one of {', '.join(sorted(_LOOPBACK_HOSTS))}). There is no auth "
            "in v0.1; binding elsewhere would expose findings to your network. "
            "See docs/collector-design.md sections 9 and 13.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=1)

    import uvicorn

    typer.echo(f"VICTOR Collector dashboard: http://{host}:{port}")
    uvicorn.run("victor_collector.ui.app:app", host=host, port=port, log_level="warning")


@app.command(name="collector-info")
def collector_info() -> None:
    """Show local collector metadata."""
    typer.echo(f"victor-collector {sync_client.VERSION}")
    typer.echo(f"local database: {storage.DEFAULT_DB_PATH}")
    creds = credentials.load()
    if creds is None:
        typer.echo("control plane: none (standalone)")
    else:
        typer.echo(f"control plane: {creds.control_plane} (collector_id={creds.collector_id})")


@plugins_app.command(name="list")
def plugins_list() -> None:
    """List registered recon plugins."""
    for plugin in plugins.list_plugins():
        flags = []
        if plugin.safe_mode:
            flags.append("safe-mode")
        if plugin.requires_credentials:
            flags.append("requires-credentials")
        typer.echo(f"{plugin.name:<24} {', '.join(flags)}")


def _describe_service_inventory(raw: dict) -> str:
    banner = raw.get("banner") or raw.get("service")
    return f"{raw.get('port')}/{raw.get('protocol')}  {banner}"


def _describe_tls_review(raw: dict) -> str:
    protocols = ", ".join(raw.get("protocols_supported", [])) or "none negotiated"
    untestable = raw.get("protocols_untestable") or []
    suffix = f" (untestable: {', '.join(untestable)})" if untestable else ""
    return f"port {raw.get('port')}: {protocols}{suffix}"


def _describe_http_header_audit(raw: dict) -> str:
    missing = raw.get("missing_headers", [])
    if missing:
        return f"{raw.get('url')}: missing {', '.join(missing)}"
    return f"{raw.get('url')}: all security headers present"


def _run_recon(
    plugin_name: str,
    target_value: str,
    safe_mode: bool,
    triage_results: bool,
    ollama_url: str,
    ollama_model: str,
    describe: Callable[[dict], str],
    extra_config: dict | None = None,
) -> None:
    """Shared execution loop for every `victor recon <plugin>` command:
    run the plugin, save each observation, optionally triage and save the
    resulting finding. `describe` renders the plugin-specific one-line
    summary — everything else is identical across plugins. `extra_config`
    passes plugin-specific options through (e.g. package-baseline-diff's
    --credential-ref).
    """
    plugin = plugins.get(plugin_name)
    if not safe_mode and not plugin.safe_mode:
        typer.secho(f"{plugin_name} only supports safe-mode operation.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"Running {plugin_name} against {target_value}...")
    try:
        observations = plugin.run(Target(value=target_value), PluginConfig(extra_config or {}))
    except RuntimeError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from None

    if not observations:
        typer.echo("No observations produced.")
        raise typer.Exit(code=0)

    for obs in observations:
        storage.save_observation(obs)
        typer.echo(f"  {describe(obs.raw)}")

        if not triage_results:
            continue
        try:
            finding = triage.triage_observation(obs, ollama_url=ollama_url, model=ollama_model)
        except httpx.HTTPError as exc:
            typer.secho(
                f"    triage skipped - couldn't reach Ollama at {ollama_url}: {exc}",
                fg=typer.colors.YELLOW,
            )
            continue
        storage.save_finding(finding)
        typer.secho(f"    -> [{finding.severity}] {finding.title}", fg=typer.colors.CYAN)

    typer.echo(f"\n{len(observations)} observation(s) saved to {storage.DEFAULT_DB_PATH}")


@recon_app.command(name="service-inventory")
def recon_service_inventory(
    target: str = typer.Argument(..., help="Host, IP, or CIDR to scan."),
    safe_mode: bool = typer.Option(True, "--safe-mode/--no-safe-mode"),
    triage_results: bool = typer.Option(
        True, "--triage/--no-triage", help="Attempt local Ollama triage after scanning."
    ),
    ollama_url: str = typer.Option(triage.DEFAULT_OLLAMA_URL, help="Local Ollama API base URL."),
    ollama_model: str = typer.Option(triage.DEFAULT_MODEL, help="Ollama model to use for triage."),
) -> None:
    """Port scan + banner grab, then (optionally) local triage."""
    _run_recon(
        "service-inventory",
        target,
        safe_mode,
        triage_results,
        ollama_url,
        ollama_model,
        _describe_service_inventory,
    )


@recon_app.command(name="tls-review")
def recon_tls_review(
    target: str = typer.Argument(..., help="Host to probe (default port 443)."),
    safe_mode: bool = typer.Option(True, "--safe-mode/--no-safe-mode"),
    triage_results: bool = typer.Option(
        True, "--triage/--no-triage", help="Attempt local Ollama triage after scanning."
    ),
    ollama_url: str = typer.Option(triage.DEFAULT_OLLAMA_URL, help="Local Ollama API base URL."),
    ollama_model: str = typer.Option(triage.DEFAULT_MODEL, help="Ollama model to use for triage."),
) -> None:
    """TLS handshake + protocol/cipher enumeration."""
    _run_recon(
        "tls-review", target, safe_mode, triage_results, ollama_url, ollama_model, _describe_tls_review
    )


@recon_app.command(name="http-header-audit")
def recon_http_header_audit(
    target: str = typer.Argument(..., help="URL or host to fetch (defaults to https://)."),
    safe_mode: bool = typer.Option(True, "--safe-mode/--no-safe-mode"),
    triage_results: bool = typer.Option(
        True, "--triage/--no-triage", help="Attempt local Ollama triage after scanning."
    ),
    ollama_url: str = typer.Option(triage.DEFAULT_OLLAMA_URL, help="Local Ollama API base URL."),
    ollama_model: str = typer.Option(triage.DEFAULT_MODEL, help="Ollama model to use for triage."),
) -> None:
    """Fetch a response and check for missing security headers."""
    _run_recon(
        "http-header-audit",
        target,
        safe_mode,
        triage_results,
        ollama_url,
        ollama_model,
        _describe_http_header_audit,
    )


def _describe_package_baseline_diff(raw: dict) -> str:
    if raw.get("status") == "baseline_established":
        return f"{raw.get('package_manager')}: baseline established ({raw.get('package_count')} packages)"
    added, removed, changed = raw.get("added", {}), raw.get("removed", {}), raw.get("changed", {})
    if not raw.get("drift_detected"):
        return f"{raw.get('package_manager')}: no drift ({raw.get('current_package_count')} packages)"
    return (
        f"{raw.get('package_manager')}: drift detected — "
        f"+{len(added)} -{len(removed)} ~{len(changed)}"
    )


@recon_app.command(name="package-baseline-diff")
def recon_package_baseline_diff(
    target: str = typer.Argument(..., help="Host to SSH into."),
    credential_ref: str = typer.Option(
        ..., "--credential-ref", help="Name of a credential file in ~/.victor/credentials/."
    ),
    triage_results: bool = typer.Option(
        True, "--triage/--no-triage", help="Attempt local Ollama triage after scanning."
    ),
    ollama_url: str = typer.Option(triage.DEFAULT_OLLAMA_URL, help="Local Ollama API base URL."),
    ollama_model: str = typer.Option(triage.DEFAULT_MODEL, help="Ollama model to use for triage."),
) -> None:
    """SSH in, list installed packages, diff against the locally stored
    baseline (established automatically on the first run against a
    given target)."""
    _run_recon(
        "package-baseline-diff",
        target,
        True,
        triage_results,
        ollama_url,
        ollama_model,
        _describe_package_baseline_diff,
        extra_config={"credential_ref": credential_ref},
    )


_EXPORTERS = {"html": export.to_html, "md": export.to_markdown, "xlsx": export.to_xlsx}


@app.command(name="report-export")
def report_export(
    fmt: str = typer.Option(..., "--format", help="html, md, or xlsx"),
    output: str = typer.Option(..., "--output", help="Output file path."),
) -> None:
    """Export locally stored findings without starting the dashboard."""
    if fmt not in _EXPORTERS:
        typer.secho(f"Unsupported format '{fmt}'. Use one of: {', '.join(_EXPORTERS)}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    findings = storage.list_findings()
    body = _EXPORTERS[fmt](findings)
    mode = "wb" if isinstance(body, bytes) else "w"
    with open(output, mode) as f:
        f.write(body)
    typer.echo(f"Wrote {len(findings)} finding(s) to {output}")


@app.command(name="findings")
def list_findings() -> None:
    """List locally triaged findings (Standalone Mode)."""
    findings = storage.list_findings()
    if not findings:
        typer.echo("No findings yet. Run `victor recon service-inventory <target>` first.")
        raise typer.Exit(code=0)
    for f in findings:
        typer.echo(f"[{f.severity:<8}] {f.title}  ({f.asset})")


if __name__ == "__main__":
    app()
