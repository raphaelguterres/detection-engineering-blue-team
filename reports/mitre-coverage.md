# Matriz de Cobertura MITRE ATT&CK

_Gerado automaticamente por `python scripts/generate_dashboard.py`. Esta é uma visão de cobertura de engenharia, não uma declaração de proteção completa contra uma técnica._

Cobertura atual: **5 técnicas** em **3 táticas**.

| Técnica | Nome | Tática | Detecção | Regra Wazuh |
| --- | --- | --- | --- | --- |
| T1218.011 | Signed Binary Proxy Execution: Rundll32 | defense-evasion | DET-WIN-RUNDLL32-001 | 100110 |
| T1059.001 | PowerShell | execution | DET-WIN-PS-ENC-001 | 100100 |
| T1053.005 | Scheduled Task/Job: Scheduled Task | persistence | DET-WIN-SCHTASKS-001 | 100120 |
| T1136.001 | Create Account: Local Account | persistence | DET-WIN-LOCALACCOUNT-001 | 100140 |
| T1547.001 | Registry Run Keys / Startup Folder | persistence | DET-WIN-RUNKEY-001 | 100130 |
