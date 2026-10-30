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
| Estado | Telemetria local confirmada; validação ponta a ponta ainda pendente |
| Regra Wazuh | `110130` |
| MITRE ATT&CK | `T1547.001` — Registry Run Keys / Startup Folder |
| Simulação | Valor temporário em `HKCU\...\Run`, removido no mesmo fluxo |
| Verificação no endpoint | A primeira tentativa não gerou Event ID 13. A configuração Sysmon do laboratório foi atualizada para incluir alterações no caminho Run; a repetição registrou um evento local e confirmou a remoção do valor |
| Verificação no Manager | A repetição não chegou à etapa de simulação porque SSH e WinRM estavam indisponíveis no preflight mais recente; nenhum alerta correlacionado foi confirmado |
| Conclusão | A coleta local de Event ID 13 está configurada; falta restabelecer acesso ao Manager e endpoint e confirmar o alerta `110130` |
| Limpeza | Valor removido; `logall_json` restaurado para `no` após o diagnóstico |

A regra permanece com fixture de regressão e contrato de rollback, mas não deve ser considerada validada operacionalmente neste laboratório até que um alerta `110130` seja observado no Manager para a nova telemetria.

## DET-WIN-LOCALACCOUNT-001 — Tentativa de criação de conta local

| Campo | Registro sanitizado |
| --- | --- |
| Estado | Simulação tentada; execução da criação falhou |
| Regra Wazuh | `110140` |
| MITRE ATT&CK | `T1136.001` — Create Account: Local Account |
| Verificação no endpoint | Dois eventos Sysmon Event ID 1 com o marcador foram observados; o usuário temporário não existia após a execução |
| Verificação no Manager | Nenhum alerta correlacionado foi encontrado; replay do evento em `wazuh-logtest` casou com `110140`, mas isso não comprova encaminhamento operacional |
| Limpeza | Confirmada; nenhum usuário temporário permaneceu |
| Conclusão | Não contabilizar como detecção; diagnosticar a falha de criação e restabelecer o transporte ao Manager antes de repetir |

## Procedimento repetível

1. Siga a [simulação de PowerShell com comando codificado](../simulations/windows/powershell-encoded-command.md).
2. Verifique o alerta da regra `110100` no Wazuh.
3. Se for necessário inspecionar eventos que não alertaram, habilite `logall_json` apenas durante uma janela curta, capture a evidência mínima e restaure o valor original.
4. Registre a execução com o [modelo de validação segura](../simulations/validation-record-template.md), fora do repositório quando houver qualquer identificador do ambiente.

## Próxima validação

Restabelecer SSH para o Kali e WinRM para o endpoint; então confirmar o preflight, encaminhamento de Sysmon ao Manager, alerta `110130` e uma execução bem-sucedida e limpa de `110140`.

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

### Bloqueio de acesso ao endpoint — 29/10/2026

A console agora exibe a tela de login do Windows para `Administrator`; não foram fornecidas nem inseridas credenciais. WinRM, RDP, SSH e SMB estão fechados nos endereços conhecidos. O agente `003` permanece `Never connected`. A contagem segue **3/5**; executar as regras `110130` e `110140` em fixtures ou no Manager não substitui simulação benigna real, evidência Sysmon, alerta correlacionado ao agente e limpeza verificada. Retomar essas duas validações quando o Windows estiver autenticado e o agente conectado.

### Retomada após reinício — 30/10/2026

A VM voltou à rede e iniciou o desktop. O agente Windows `004` (`WIN-TP3GFAE2OCB`) ficou ativo. O listener WinRM HTTP respondeu ao `Test-WSMan`, mas a execução remota com a identidade atual foi recusada porque são exigidas credenciais explícitas; não há credencial DPAPI local disponível. A conta autenticada no desktop da VM não autentica automaticamente a sessão WinRM iniciada pelo controlador.

As duas simulações continuam pendentes e a contagem permanece **3/5**. Nenhuma simulação foi executada nesta retomada. O próximo passo é disponibilizar credencial WinRM autorizada em arquivo DPAPI local; depois validar os serviços e o Event ID 13 antes das simulações `110130` e `110140`.

O arquivo DPAPI foi criado no controlador e importado como credencial `Administrator`, mas WinRM ainda não autentica: o controlador não confia no alvo, e a configuração de `TrustedHosts` exige privilégio administrativo. A tentativa de escrita foi negada e não alterou o sistema. A contagem permanece **3/5**; nenhuma simulação operacional foi executada.
