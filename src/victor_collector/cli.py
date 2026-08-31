"""CLI surface — matches docs/collector-design.md §4 in victor-recon-console.

`victor recon <plugin> <target>` is real end to end right now: run the
plugin, save the observation, triage it locally against Ollama if
reachable, save and print the resulting finding. `enroll`/`run`/`ui` are
present as real commands but not yet implemented — there's no cloud API
to enroll against yet, and the local web UI is a separate build step.
"""

from __future__ import annotations

import httpx
import typer

from victor_collector import plugins, storage, triage
from victor_collector.plugins import PluginConfig
from victor_collector.models import Target

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
        "`victor plugins list` to run recon and inspect stored findings.",
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
    plugin = plugins.get("service-inventory")
    if not safe_mode and not plugin.safe_mode:
        typer.secho("service-inventory only supports safe-mode operation.", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.echo(f"Running service-inventory against {target}...")
    try:
        observations = plugin.run(Target(value=target), PluginConfig())
    except RuntimeError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=1) from None

    if not observations:
        typer.echo("No open ports found.")
        raise typer.Exit(code=0)

    for obs in observations:
        storage.save_observation(obs)
        port = obs.raw.get("port")
        banner = obs.raw.get("banner") or obs.raw.get("service")
        typer.echo(f"  {port}/{obs.raw.get('protocol')}  {banner}")

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
