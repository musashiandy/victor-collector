"""Report export for Standalone Mode findings (docs/collector-design.md §9).

HTML, Markdown, and XLSX are implemented — all stdlib-or-pure-Python
dependencies. PDF (weasyprint in the design doc) is deliberately deferred:
it needs system-level Pango/Cairo libraries that pip alone won't install
on Windows, which isn't worth the fragility for a v0.1. HTML export
already covers "something to hand someone" in the meantime.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone

from openpyxl import Workbook

from victor_collector.models import Finding

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))


def to_markdown(findings: list[Finding]) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = ["# VICTOR Collector — Findings Report", f"Generated {generated}\n"]
    for f in _sorted(findings):
        lines.append(f"## [{f.severity}] {f.title}")
        lines.append(f"- **Asset**: {f.asset}")
        lines.append(f"- **Confidence**: {f.confidence}%")
        lines.append(f"- **Tags**: {', '.join(f.tags) or 'none'}")
        lines.append(f"\n**Evidence**\n\n```\n{f.evidence}\n```\n")
        lines.append(f"**Remediation**\n\n{f.remediation}\n")
    if not findings:
        lines.append("_No findings recorded yet._")
    return "\n".join(lines)


def to_html(findings: list[Finding]) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = []
    for f in _sorted(findings):
        rows.append(
            f"""
            <article class="finding sev-{f.severity.lower()}">
              <header><span class="badge">{f.severity}</span> {f.title}</header>
              <dl>
                <dt>Asset</dt><dd>{f.asset}</dd>
                <dt>Confidence</dt><dd>{f.confidence}%</dd>
                <dt>Tags</dt><dd>{', '.join(f.tags) or 'none'}</dd>
              </dl>
              <p class="label">Evidence</p><pre>{f.evidence}</pre>
              <p class="label">Remediation</p><p>{f.remediation}</p>
            </article>
            """
        )
    body = "\n".join(rows) if findings else "<p>No findings recorded yet.</p>"
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>VICTOR Collector — Findings Report</title>
<style>
  body {{ background:#131924; color:#e8ecf1; font-family: 'Segoe UI', sans-serif; padding: 2rem; max-width: 900px; margin: 0 auto; }}
  header, .meta {{ color: #8a95a6; }}
  .finding {{ border: 1px solid #2c3444; border-radius: 8px; padding: 1rem 1.25rem; margin: 1rem 0; }}
  .finding > header {{ font-size: 1.1rem; font-weight: 600; margin-bottom: .5rem; }}
  .badge {{ font-family: monospace; font-size: .7rem; text-transform: uppercase; padding: .15rem .5rem;
    border-radius: 999px; margin-right: .5rem; background:#2c3444; }}
  .sev-critical .badge, .sev-high .badge {{ background:#5c2020; color:#ff8a8a; }}
  .sev-medium .badge {{ background:#5c4a1a; color:#ffd27a; }}
  dl {{ display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; font-size: .85rem; color:#b7bfcc; }}
  .label {{ font-size: .7rem; text-transform: uppercase; letter-spacing: .08em; color:#8a95a6; margin: .75rem 0 .25rem; }}
  pre {{ white-space: pre-wrap; background:#0d1119; padding: .75rem; border-radius: 6px; font-size: .8rem; }}
</style></head>
<body>
<h1>VICTOR Collector &mdash; Findings Report</h1>
<p class="meta">Generated {generated}</p>
{body}
</body></html>"""


def to_xlsx(findings: list[Finding]) -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "Findings"
    ws.append(["Severity", "Title", "Asset", "Confidence", "Tags", "Evidence", "Remediation"])
    for f in _sorted(findings):
        ws.append(
            [f.severity, f.title, f.asset, f.confidence, ", ".join(f.tags), f.evidence, f.remediation]
        )
    for col in ws.columns:
        width = max((len(str(c.value)) for c in col if c.value), default=10)
        ws.column_dimensions[col[0].column_letter].width = min(width + 2, 60)

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
