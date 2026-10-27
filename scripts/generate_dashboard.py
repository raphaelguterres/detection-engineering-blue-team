"""Generate review-friendly Markdown dashboards from the detection catalog."""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from quality_gate import CATALOG, ROOT, parse_catalog

DASHBOARD = ROOT / "docs" / "dashboard.md"
MATRIX = ROOT / "reports" / "mitre-coverage.md"
DATA = ROOT / "dashboard" / "data.js"


def table(rows: list[list[str]], headers: list[str]) -> str:
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return "\n".join(lines)


def main() -> None:
    entries = parse_catalog(CATALOG.read_text(encoding="utf-8"))
    DASHBOARD.parent.mkdir(parents=True, exist_ok=True)
    MATRIX.parent.mkdir(parents=True, exist_ok=True)
    DATA.parent.mkdir(parents=True, exist_ok=True)
    tactics = Counter(str(item["tactic"]) for item in entries)
    severities = Counter(str(item["severity"]) for item in entries)
    statuses = Counter(str(item["status"]) for item in entries)
    techniques = sorted({str(item["technique"]) for item in entries})

    tactic_rows = [[tactic, str(count)] for tactic, count in sorted(tactics.items())]
    severity_rows = [[severity, str(count)] for severity, count in sorted(severities.items())]
    status_rows = [[status, str(count)] for status, count in sorted(statuses.items())]
    rule_rows = [
        [str(item["id"]), str(item["technique"]), str(item["tactic"]), str(item["severity"]), str(item["status"])]
        for item in sorted(entries, key=lambda value: str(value["id"]))
    ]

    DASHBOARD.write_text(
        "# Dashboard de Detection Engineering\n\n"
        "_Gerado automaticamente por `python scripts/generate_dashboard.py`. Não edite manualmente._\n\n"
        "## Resumo\n\n"
        f"- **{len(entries)}** detecções versionadas\n"
        f"- **{len(techniques)}** técnicas MITRE ATT&CK cobertas\n"
        f"- **{len(tactics)}** táticas ATT&CK cobertas\n"
        f"- **{len(entries)}** cenários positivos e **{len(entries)}** cenários benignos de regressão\n\n"
        "## Distribuição por tática\n\n"
        + table(tactic_rows, ["Tática", "Detecções"])
        + "\n\n## Distribuição por severidade\n\n"
        + table(severity_rows, ["Severidade", "Detecções"])
        + "\n\n## Status do catálogo\n\n"
        + table(status_rows, ["Status", "Detecções"])
        + "\n\n## Detecções atuais\n\n"
        + table(rule_rows, ["Detecção", "MITRE", "Tática", "Severidade", "Status"])
        + "\n",
        encoding="utf-8",
    )

    matrix_rows = [
        [
            str(item["technique"]),
            str(item["technique_name"]),
            str(item["tactic"]),
            str(item["id"]),
            str(item["rule_id"]),
        ]
        for item in sorted(entries, key=lambda value: (str(value["tactic"]), str(value["technique"])))
    ]
    MATRIX.write_text(
        "# Matriz de Cobertura MITRE ATT&CK\n\n"
        "_Gerado automaticamente por `python scripts/generate_dashboard.py`. Esta é uma visão de cobertura de engenharia, não uma declaração de proteção completa contra uma técnica._\n\n"
        f"Cobertura atual: **{len(techniques)} técnicas** em **{len(tactics)} táticas**.\n\n"
        + table(matrix_rows, ["Técnica", "Nome", "Tática", "Detecção", "Regra Wazuh"])
        + "\n",
        encoding="utf-8",
    )
    DATA.write_text(
        "window.DETECTION_DASHBOARD = "
        + json.dumps(
            {
                "summary": {
                    "detections": len(entries),
                    "techniques": len(techniques),
                    "tactics": len(tactics),
                    "regression_pairs": len(entries),
                },
                "tactics": dict(sorted(tactics.items())),
                "severities": dict(sorted(severities.items())),
                "detections": [
                    {
                        "id": item["id"],
                        "technique": item["technique"],
                        "tactic": item["tactic"],
                        "severity": item["severity"],
                        "status": item["status"],
                        "simulation": item["simulation"],
                    }
                    for item in sorted(entries, key=lambda value: str(value["id"]))
                ],
            },
            ensure_ascii=False,
            indent=2,
        )
        + ";\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
