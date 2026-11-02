# Fase 3 — cinco regras personalizadas visíveis no Wazuh Discover

**Janela de verificação:** 01/11/2026 na VM Windows Server; a última atualização de PowerShell ocorreu em **02/11/2026 00:22 UTC**. **Escopo do resultado:** eventos benignos reais, alertas indexados e visíveis no Dashboard. A comparação independente do mesmo ID com o arquivo do Manager **continua pendente para os eventos pós-deploy**.

## Evidências operacionais reais

Foi usado o Discover autenticado da VM Windows Server com data view **`wazuh-alerts-*`**, último intervalo de 24 horas, busca DQL individual `rule.id: <ID> and agent.id: 004`. Os resultados são documentos de alertas indexados, **não** registros artificiais do `wazuh-logtest`.

| Regra personalizada | Evidência no Wazuh Dashboard | Horário exibido pela VM | Origem |
| --- | ---: | --- | --- |
| `110100` — PowerShell EncodedCommand | **1 alerta** | 01/11 16:22:15.606 | Nova execução benigna **após ajuste de 110100** |
| `110110` — Rundll32 em caminho gravável | **1 alerta** | 01/11 15:19:45.738 | Reteste benigno após implantação Sysmon |
| `110120` — Schtasks `/create` | **1 alerta** | 01/11 15:19:52.407 | Reteste benigno após implantação Sysmon |
| `110130` — Registry Run Key | **1 alerta** | 01/11 13:10:26.157 | Reteste benigno anterior, com remoção confirmada |
| `110140` — tentativa de conta local | **2 alertas** | 01/11 13:11:05.931 e 13:11:05.997 | Reteste benigno anterior, conta temporária desabilitada e removida |

A VM apresenta horários locais em UTC−8 nesta sessão; os registros originais e a marca temporal do teste são UTC. Os alertas foram confirmados **um por vez**, após filtro pelos IDs exatos; todos pertencem ao agente `004`. **Total: cinco IDs personalizados distintos visíveis no Indexer/Dashboard.**

### Último conflito `110100` versus `92057`

No primeiro reteste pós-deploy, a regra personalizada `110100` não aparecia no Discover e a regra nativa `92057` classificou o PowerShell às **15:19:37.962** na VM. A regra `92057` é de nível 12, derivada de `sysmon_event1`, e exige PowerShell como processo pai e comando codificado.

Foram comparados dois candidatos em **cópia descartável** da árvore real do Wazuh 4.14.9:

1. `<if_sid>92057</if_sid>`: 11/11 fixtures existentes passaram, mas falhou **um novo positivo** de PowerShell codificado iniciado por `cmd.exe` (**11/12**) — candidato rejeitado por redução de cobertura.
2. `<if_sid>61603,92057</if_sid>`: **12/12 fixtures aprovados**, cobrindo pai PowerShell e `cmd.exe`, mais negativos e as demais quatro regras. Esse candidato foi integrado ao `main` pelo [PR #18](https://github.com/raphaelguterres/detection-engineering-blue-team/pull/18), CI **success**, squash `929709b53e9d2343a47e29305c171c1966d853d8`.

### Implantação controlada de uma única regra

Após o PR aprovado, a regra `110100` foi implantada separadamente com backup privado, comparação do SHA-256 do XML anterior, validação `wazuh-analysisd -t`, reinicialização do Manager e espera pela saúde dos serviços e agente.

- Backup privado específico para **`110100`**, com manifesto e rollback da regra apenas: `/home/kali/.local/share/wazuh-evidence/phase3/rule-deploy-20261102T002051Z`.
- Nova `110100` instalada e hash validado, sem alterar os XML `110110`/`110120` já funcionando.
- Um novo cenário benigno PowerShell executado dentro do Windows Server, **`LOCAL_TEST_STATUS=PASS`**, 1 evento Sysmon local e `cleanup=not_needed`.
- Execução concluída em aproximadamente **02/11/2026 00:22 UTC**; o documento `110100` apareceu no Discover às **01/11 16:22:15.606** na hora local da VM.
- Inspeção final: Manager, Indexer e Dashboard **running**, agente `004` **Active**, `wazuh-analysisd -t` **PASS**, `logall_json=no`. Os dois outros hashes após a implantação permaneceram idênticos aos registrados antes dela.

**Nenhuma alteração de regra nativa, credencial, índice ou histórico.** Não foram reexecutados os cenários `110110`, `110120`, `110130` e `110140` depois da última alteração.

## O que está comprovado versus pendente

| Nível | Resultado |
| --- | --- |
| Execuções benignas no Windows Server e coleta Sysmon | **Comprovadas** pelos testes locais |
| Testes isolados de regras (incluindo negativos) | **12/12 aprovados** na árvore descartável do Wazuh 4.14.9 |
| Regras personalizadas distintas indexadas e visíveis no Discover | **5/5 comprovadas**, com 6 alertas indexados |
| Igualdade entre os documentos vistos e os **IDs originais dos alertas em `alerts.json` do Manager** | **Não conferida independentemente nesta etapa** |
| Correlação formal ponta a ponta Manager → Indexer → Dashboard por **mesmo ID, regra, agente e timestamp** para todas as cinco regras | **Pendente**; não elevar automaticamente a `verified` |
| Falha histórica de indexação 27–30/10/2026 | **Pendente separada**; não usar resultados atuais como replay histórico |

Em rodada anterior, `110130` e `110140` já tinham eventos correlacionados por identidade exata entre Manager e Indexer, mas a nova rodada de UI deve ser distinguida dos eventos de cada janela. A ferramenta de acesso remoto bloqueou a consulta automatizada ao arquivo de alertas do Manager, portanto **não** foi tentada outra rota para contornar esse controle.

## Como concluir o último gate, sem reiniciar ou repetir testes

1. Em uma sessão local/autorizada de auditoria do laboratório, usar as ferramentas já versionadas [`scripts/phase3_compare_alert_exports.py`](../scripts/phase3_compare_alert_exports.py) e [`scripts/phase3-run-offline.ps1`](../scripts/phase3-run-offline.ps1) com **duas exportações privadas e independentes** do Manager e Indexer na janela dos eventos acima.
2. Comparar `id`, `rule.id`, `agent.id`, `timestamp` de cada evento com os documentos localizados no Discover, respeitando o fuso horário.
3. Após revisão e autorização da evidência, documentar somente conclusões e contagens sanitizadas e atualizar a [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4); só marcar `verified` se a identidade for comprovada em todas as três etapas.
4. Não reativar `logall_json`, não repetir simulações e não reiniciar containers apenas por ausência da comparação final. O backup de `110100` permanece restrito e não deve ser confundido com o backup anterior das três regras.

**Conceito de conclusão:** `5/5 alertas personalizados indexados e visíveis no Dashboard` está **comprovado**; `5/5 Manager → Indexer → Dashboard formalmente correlacionados` ainda **não**.
