"""CLI surface - matches docs/collector-design.md §4 in victor-recon-console.

`victor recon <plugin> <target>` is real end to end right now: run the
plugin, save the observation, triage it locally against Ollama if
reachable, save and print the resulting finding. `enroll`/`run`/`ui` are
present as real commands but not yet implemented - there's no cloud API
to enroll against yet, and the local web UI is a separate build step.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
import typer

from victor_collector import plugins, storage, triage
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
    typer.secho(
        "Not implemented yet - there is no cloud API to enroll against "
        "(BACKLOG.md M0 in victor-recon-console). Run recon commands standalone "
        "in the meantime: `victor recon service-inventory <target>`.",
        fg=typer.colors.YELLOW,
    )
    raise typer.Exit(code=1)


@app.command()
def status() -> None:
    """Show collector enrollment status."""
    typer.echo("Standalone - not enrolled with any control plane.")


@app.command(name="run")
def run_daemon() -> None:
    """Cloud-connected daemon mode: heartbeat + task poll loop."""
    typer.secho(
        "Not implemented yet - depends on `victor enroll` and the cloud API. "
        "See docs/collector-design.md §7 for the wire protocol this will speak.",
        fg=typer.colors.YELLOW,
    )
    raise typer.Exit(code=1)


@app.command()
def ui(port: int = typer.Option(8787, help="Loopback-only local dashboard port.")) -> None:
    """Standalone Mode local web UI (Sessions/Targets/Findings/Export)."""
    typer.secho(
        "Not implemented yet. For now, use `victor recon <plugin> <target>` and "
        "`victor findings` to run recon and inspect stored results.",
        fg=typer.colors.YELLOW,
    )
    raise typer.Exit(code=1)


@app.command(name="collector-info")
def collector_info() -> None:
    """Show local collector metadata."""
    typer.echo("victor-collector 0.1.0")
    typer.echo(f"local database: {storage.DEFAULT_DB_PATH}")
    typer.echo("control plane: none (standalone)")


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
) -> None:
    """Shared execution loop for every `victor recon <plugin>` command:
    run the plugin, save each observation, optionally triage and save the
    resulting finding. `describe` renders the plugin-specific one-line
    summary — everything else is identical across plugins.
    """
    plugin = plugins.get(plugin_name)
    if not safe_mode and not plugin.safe_mode:
        typer.secho(f"{plugin_name} only supports safe-mode operation.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"Running {plugin_name} against {target_value}...")
    try:
        observations = plugin.run(Target(value=target_value), PluginConfig())
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
