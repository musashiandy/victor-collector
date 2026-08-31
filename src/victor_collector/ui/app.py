"""Standalone Mode local web UI (docs/collector-design.md §9).

No auth in v0.1 — mitigated by loopback-only binding, enforced by the CLI
launcher (see cli.py's `ui` command), not here. This module doesn't know
or care what host it's bound to; that decision belongs one layer up.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response

from victor_collector import export, storage

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="VICTOR Collector", docs_url=None, redoc_url=None)

_EXPORT_CONTENT_TYPES = {
    "html": "text/html",
    "md": "text/markdown",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/favicon.svg")
def favicon() -> Response:
    return Response(
        content=(STATIC_DIR / "favicon.svg").read_bytes(),
        media_type="image/svg+xml",
    )


@app.get("/api/findings")
def api_findings() -> list[dict]:
    return [f.model_dump() for f in storage.list_findings()]


@app.get("/api/stats")
def api_stats() -> dict:
    findings = storage.list_findings()
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    return {"total": len(findings), "by_severity": by_severity}


@app.get("/export/{fmt}")
def export_findings(fmt: str) -> Response:
    if fmt not in _EXPORT_CONTENT_TYPES:
        return Response(
            content=f"Unsupported format '{fmt}'. Use one of: {', '.join(_EXPORT_CONTENT_TYPES)}",
            status_code=400,
        )

    findings = storage.list_findings()
    if fmt == "html":
        body: bytes | str = export.to_html(findings)
    elif fmt == "md":
        body = export.to_markdown(findings)
    else:
        body = export.to_xlsx(findings)

    return Response(
        content=body,
        media_type=_EXPORT_CONTENT_TYPES[fmt],
        headers={"Content-Disposition": f"attachment; filename=victor-findings.{fmt}"},
    )
