# Dashboard de Detection Engineering

_Gerado automaticamente por `python scripts/generate_dashboard.py`. Não edite manualmente._

## Resumo

- **5** detecções versionadas
- **5** técnicas MITRE ATT&CK cobertas
- **3** táticas ATT&CK cobertas
- **5** cenários positivos e **5** cenários benignos de regressão

## Distribuição por tática

| Tática | Detecções |
| --- | --- |
| defense-evasion | 1 |
| execution | 1 |
| persistence | 3 |

## Distribuição por severidade

| Severidade | Detecções |
| --- | --- |
| high | 3 |
| medium | 2 |

## Status do catálogo

| Status | Detecções |
| --- | --- |
| production | 5 |

## Detecções atuais

| Detecção | MITRE | Tática | Severidade | Status |
| --- | --- | --- | --- | --- |
| DET-WIN-LOCALACCOUNT-001 | T1136.001 | persistence | high | production |
| DET-WIN-PS-ENC-001 | T1059.001 | execution | high | production |
| DET-WIN-RUNDLL32-001 | T1218.011 | defense-evasion | medium | production |
| DET-WIN-RUNKEY-001 | T1547.001 | persistence | high | production |
| DET-WIN-SCHTASKS-001 | T1053.005 | persistence | medium | production |
