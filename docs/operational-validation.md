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

## DET-WIN-RUNKEY-001 — Run Key temporária

| Campo | Registro sanitizado |
| --- | --- |
| Estado | Bloqueado por pré requisito de telemetria |
| Regra Wazuh | `110130` |
| MITRE ATT&CK | `T1547.001` — Registry Run Keys / Startup Folder |
| Simulação | Valor temporário em `HKCU\...\Run`, removido no mesmo fluxo |
| Verificação no endpoint | A criação e a remoção foram concluídas; o Sysmon não registrou Event ID 13 para o teste |
| Verificação no Manager | Nenhum evento do teste chegou ao arquivo de eventos; nenhum alerta `110130` foi gerado |
| Conclusão | Habilitar a coleta Sysmon de Event ID 13 antes de repetir a validação |
| Limpeza | Valor removido; `logall_json` restaurado para `no` após o diagnóstico |

A regra permanece com fixture de regressão e contrato de rollback, mas não deve ser considerada validada operacionalmente neste laboratório até a telemetria Event ID 13 estar disponível.

## Procedimento repetível

1. Siga a [simulação de PowerShell com comando codificado](../simulations/windows/powershell-encoded-command.md).
2. Verifique o alerta da regra `110100` no Wazuh.
3. Se for necessário inspecionar eventos que não alertaram, habilite `logall_json` apenas durante uma janela curta, capture a evidência mínima e restaure o valor original.
4. Registre a execução com o [modelo de validação segura](../simulations/validation-record-template.md), fora do repositório quando houver qualquer identificador do ambiente.

## Próxima validação

Validar `DET-WIN-LOCALACCOUNT-001` com uma conta local temporária, sem privilégios e removida no mesmo fluxo, após confirmação explícita do operador.

## Automação preparada — 28/10/2026

Foi adicionado o [executor remoto com documentação](lab-automation.md). As verificações locais cobrem correlação de alertas, falhas de transporte, conflitos de regras e restauração de backup, além de sintaxe PowerShell. O SSH do Kali e a identificação WinRM do Windows responderam; a autenticação remota ainda não foi estabelecida. Não houve nova simulação nas VMs por este executor e os três resultados operacionais anteriores permanecem o total confirmado.

A tentativa manual mais recente de `net user` exibiu ajuda de sintaxe, sem confirmação de criação. Esse resultado não valida a regra `110140`. O cenário automático usa nome único, conta desabilitada, senha por entrada padrão e remoção no mesmo fluxo; permanece pendente de validação real.

O CI da automação foi aprovado no GitHub. Na primeira retomada, ambas as VMs estavam salvas e o Kali permaneceu bloqueado. Na retomada seguinte, as VMs voltaram à execução e o Kali já estava desbloqueado. Nenhuma nova validação operacional foi contabilizada durante essas preparações.

### Retomada de acesso — 29/10/2026

O Kali foi encontrado desbloqueado em uma sessão root, com ambas as VMs em execução. A entrada de texto pelo controle gráfico falhou com `0x80070005` antes da execução da consulta da chave SSH. A automação permanece pendente de autenticação; o total operacional confirmado continua sendo três de cinco detecções.

Na tentativa seguinte, a porta SSH do Kali respondeu, mas a identidade do host não estava no `known_hosts`, então a conexão estrita foi recusada. WinRM no endereço observado do Windows não respondeu. O executor não enviou comandos e nenhuma nova detecção foi validada.

### Atualização — 29/10/2026

O acesso SSH ao Manager foi estabelecido com chave dedicada e host verificado. As cinco regras versionadas foram implantadas e os dez fixtures de regressão passaram no `wazuh-logtest`: cinco positivos casaram com as regras esperadas (`110100`, `110110`, `110120`, `110130`, `110140`) e cinco controles negativos não casaram.

Isso não altera a contagem operacional: **3/5**. As regras `110130` e `110140` continuam sem validação ponta a ponta no Windows. O agente dedicado da VM está registrado como `Never connected`, WinRM não respondeu e a sessão da VM não atualizou pelo Guest Additions. Nenhuma simulação foi executada nessa retomada. O fixture positivo de `110130` confirma apenas o comportamento da regra no Manager; a telemetria Sysmon Event ID 13 ainda precisa ser observada no endpoint.
