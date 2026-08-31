from openpyxl import load_workbook
import io

from victor_collector.export import to_html, to_markdown, to_xlsx
from victor_collector.models import Finding

SAMPLE = [
    Finding(
        title="Outdated SSH Service",
        severity="High",
        confidence=91,
        asset="10.10.10.25:22",
        evidence="Banner: OpenSSH_7.4",
        remediation="Upgrade OpenSSH.",
        tags=["ssh"],
        source_observation_id="obs-1",
    ),
    Finding(
        title="Exposed Admin Panel",
        severity="Critical",
        confidence=88,
        asset="https://10.10.10.25/admin",
        evidence="No auth required.",
        remediation="Restrict access.",
        tags=["web"],
        source_observation_id="obs-2",
    ),
]


def test_markdown_sorts_by_severity_and_includes_all_findings():
    doc = to_markdown(SAMPLE)
    critical_pos = doc.index("Exposed Admin Panel")
    high_pos = doc.index("Outdated SSH Service")
    assert critical_pos < high_pos  # Critical sorts before High
    assert "OpenSSH_7.4" in doc


def test_markdown_handles_empty_findings():
    doc = to_markdown([])
    assert "No findings recorded yet" in doc


def test_html_escapes_nothing_but_includes_all_fields():
    doc = to_html(SAMPLE)
    assert "Outdated SSH Service" in doc
    assert "Exposed Admin Panel" in doc
    assert "sev-critical" in doc
    assert "sev-high" in doc


def test_xlsx_produces_readable_workbook_with_header_and_rows():
    data = to_xlsx(SAMPLE)
    wb = load_workbook(io.BytesIO(data))
    ws = wb.active
    header = [c.value for c in next(ws.iter_rows(min_row=1, max_row=1))]
    assert header == ["Severity", "Title", "Asset", "Confidence", "Tags", "Evidence", "Remediation"]
    rows = list(ws.iter_rows(min_row=2, values_only=True))
    assert len(rows) == 2
    assert rows[0][0] == "Critical"  # sorted first
