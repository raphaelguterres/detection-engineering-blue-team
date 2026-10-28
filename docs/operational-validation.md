# Validação operacional registrada

## DET-WIN-PS-ENC-001 — PowerShell codificado

| Campo | Registro sanitizado |
| --- | --- |
| Estado | Detectado em laboratório isolado e autorizado |
| Regra Wazuh | `110100` |
| MITRE ATT&CK | `T1059.001` — PowerShell |
| Fonte de telemetria | Sysmon, Event ID 1, via agente Wazuh para o Manager |
| Simulação | PowerShell com `-EncodedCommand` que apenas escreve `DETECTION-TEST` no console |
| Resultado no Manager | Evento chegou ao arquivo de eventos e a regra `110100` gerou alerta |
| Controle temporário | `logall_json` habilitado somente para diagnóstico e restaurado para `no` após a validação |
| Dados excluídos | Logs brutos, IPs internos, identificadores de agente, usuários, timestamps e screenshots |

## Interpretação

A simulação comprovou a cadeia operacional completa: a criação de processo foi registrada pelo Sysmon, coletada pelo agente, analisada pelo Wazuh Manager e correlacionada pela regra local. A validação não substitui os fixtures de regressão nem o quality gate; ela os complementa com evidência de execução em ambiente isolado.

## DET-WIN-RUNDLL32-001 — Rundll32 em caminho gravável

| Campo | Registro sanitizado |
| --- | --- |
| Estado | Detectado em laboratório isolado e autorizado |
| Regra Wazuh | `110110` |
| MITRE ATT&CK | `T1218.011` — Signed Binary Proxy Execution: Rundll32 |
| Fonte de telemetria | Sysmon, Event ID 1, via agente Wazuh para o Manager |
| Simulação | `rundll32.exe` apontando para DLL inexistente sob `C:\Users\Public` |
| Resultado no Manager | A regra `110110` gerou alerta após a criação de processo |
| Segurança da execução | O Windows informou que o módulo não foi encontrado; nenhuma DLL foi criada ou carregada |
| Dados excluídos | Logs brutos, IPs internos, identificadores de agente, usuários, timestamps e screenshots |

A execução confirma que a condição de caminho gravável pelo usuário é correlacionada pelo Wazuh sem depender de DLL de teste ou de carregamento de código.

## DET-WIN-SCHTASKS-001 — Tarefa agendada descartável

| Campo | Registro sanitizado |
| --- | --- |
| Estado | Detectado em laboratório isolado e autorizado |
| Regra Wazuh | `110120` |
| MITRE ATT&CK | `T1053.005` — Scheduled Task/Job: Scheduled Task |
| Fonte de telemetria | Sysmon, Event ID 1, via agente Wazuh para o Manager |
| Simulação | Criação de `DetectionEngineeringDemo` com execução única, seguida de remoção imediata |
| Resultado no Manager | A regra `110120` gerou alerta após a criação da tarefa |
| Segurança da execução | A tarefa não foi executada e foi removida no mesmo fluxo |
| Dados excluídos | Logs brutos, IPs internos, identificadores de agente, usuários, timestamps e screenshots |

A execução confirma que a criação de tarefa por `schtasks.exe` é correlacionada pela regra local e pode ser validada sem manter um artefato de persistência no laboratório.

## Procedimento repetível

1. Siga a [simulação de PowerShell com comando codificado](../simulations/windows/powershell-encoded-command.md).
2. Verifique o alerta da regra `110100` no Wazuh.
3. Se for necessário inspecionar eventos que não alertaram, habilite `logall_json` apenas durante uma janela curta, capture a evidência mínima e restaure o valor original.
4. Registre a execução com o [modelo de validação segura](../simulations/validation-record-template.md), fora do repositório quando houver qualquer identificador do ambiente.

## Próxima validação

Validar `DET-WIN-RUNDLL32-001` com a fixture sintética e a simulação segura correspondente antes de promover qualquer alteração de tuning.
