# Fase 3 — checklist de aceitação pós-implantação (01/11/2026)

**Status comprovado:** correção das três regras **instalada** no Wazuh Manager 4.14.9; regressão em árvore descartável **11/11 casos aprovados**; três simulações benignas **executadas no Windows Server** com Sysmon local e limpeza. **Aceitação Manager → Indexer → Dashboard ainda NÃO comprovada para os três alertas gerados após o deploy.**

## Sequência e limites

1. Cinco regras customizadas estão versionadas em `main`. O PR [#15](https://github.com/raphaelguterres/detection-engineering-blue-team/pull/15) adicionou `<if_group>sysmon_event1</if_group>` às regras `110100`, `110110`, `110120`.
2. Em 01/11/2026, as cinco regras candidatas passaram em **11 casos de regressão**, com `wazuh-logtest-legacy` em cópia descartável da árvore Windows do **Wazuh 4.14.9** (positivos e negativos). Isso **não substitui** detecção ao vivo.
3. A instalação com backup privado passou na segunda tentativa. O instalador verificou `wazuh-analysisd -t`, hashes das três regras, serviços essenciais, agente `004` ativo e `logall_json=no`.
4. Diretório privado de rollback: `/home/kali/.local/share/wazuh-evidence/phase3/rule-deploy-20261101T231821Z`. Os três XML originais e seu manifesto permaneceram fora do GitHub. A primeira tentativa apresentou erro de prontidão; inspeção independente confirmou restauração dos três hashes originais, antes do deploy final.
5. Na mesma data, após a instalação, a VM Windows Server executou os três cenários benignos com resultados `LOCAL_OK=True`: PowerShell **1** evento Sysmon, Rundll32 **1** e Schtasks **2**, com limpeza de tarefa verificada. Identificadores únicos devem permanecer **privados**.
6. A consulta automática dos alertas pós-deploy foi bloqueada pelo controle de segurança da ferramenta remota, e o Dashboard Discover redirecionou para o login. **Não houve evidência nova de correspondência entre Manager, Indexer e Dashboard**, apesar dos testes locais aprovados. Não contornar bloqueios por outro canal.

## Gate operacional pendente: sem gerar novos eventos

**Janela sugerida para inspeção:** 01/11/2026, aproximadamente **23:18–23:25 UTC**. Confirmar o horário real do evento ao consultar a fonte, evitando inferir falsos negativos a partir da janela. A interface pode apresentar timezone local.

| Regra | Expectativa de evidência nova no Manager | Indexer | Dashboard |
|---|---|---|---|
| `110100` | Alerta `rule.id=110100` e mesmo marcador da execução PowerShell pós-deploy; **não aceitar só a nativa 92057** | Mesmo `id`, `rule.id`, `agent.id`, `timestamp` | Mesmo documento no Discover |
| `110110` | Alerta customizado `110110` correspondente ao Rundll32 | Mesma identidade exata | Mesmo documento no Discover |
| `110120` | Alerta customizado `110120` correspondente ao Schtasks `/create` | Mesma identidade exata | Mesmo documento no Discover |

Todas as três verificações precisam ter agente `004`, **evento novo posterior à implantação** e marcadores individuais. Alertas históricos, negativos dos testes offline e outras regras não são substitutos.

### Acesso autorizado e exportações privadas

Se a sessão do Discover pedir autenticação, **o operador deve entrar pessoalmente com suas credenciais**. Não compartilhar senhas, tokens, certificados, arquivos brutos ou screenshots contendo identificadores. Se houver indisponibilidade de login, registrar `dashboard=unknown`, não `missing`.

Para a comparação Manager/Indexer, **reutilizar**:
- [Comparador offline de alertas por identidade](phase3-historical-alert-correlation.md): `scripts/phase3_compare_alert_exports.py`.
- [Executor de evidência offline](phase3-one-command-offline.md): `scripts/phase3-run-offline.ps1`.
- [Gate conservador da Fase 3](phase3-evidence-handoff.md), que deixa Dashboard como `unknown` até conferência independente.

Esses utilitários não extraem dados do SIEM. A aquisição deve ocorrer pelos métodos **autorizados localmente**, com fontes Manager e Indexer distintas, em diretório privado `.lab/`, sem enviar material original ao GitHub. O comparador informa apenas **contagens agregadas** com correspondência exata de `id`, `rule.id`, `agent.id`, `timestamp`.

### Interpretação sem conclusão precipitada

- **Manager sem alerta customizado, apesar do Sysmon local:** revisar hierarquia de regras, prioridade, evento decodificado e outras decisões, sem marcar `PASS`.
- **Manager com alerta, Indexer sem o mesmo documento:** verificar Filebeat, índice e janela do registro, sem deduzir automaticamente queda da ingestão.
- **Indexer com documento, Discover sem o mesmo evento:** revisar login, permissões, `wazuh-alerts-*`, janela, timezone e filtro.
- **Três etapas com a mesma identidade:** salvar evidência sanitizada e conferir também ausência de falsos positivos para então considerar `verified`.
- **Restrição de acesso ou retenção insuficiente:** `unknown`/`inconclusive`, nunca presumir falha nem aprovação.

## Não repetir nem reconfigurar sem motivo

Não reiniciar Wazuh, não ativar `logall_json`, não instalar regras outra vez, não executar a simulação novamente e não refazer histórico de 27–30/10 só porque o Dashboard pediu login.

O rollback deve ser considerado **somente após confirmar regressão operacional** e consultar o manifesto e os hashes do backup privado. A implantação atual passou na validação sintática; há um script privado de rollback no laboratório, fora do repositório, que requer revisão do operador antes da execução.

## Saída de aceitação esperada

Publicar no repositório **somente**: IDs das regras, contagens por etapa, decisão (`verified`/`partial`/`inconclusive`), janela em UTC, resultado de limpeza e confirmação independente da mesma identidade de evento no Discover. Não publicar agentes, marcadores únicos, hosts internos ou eventos brutos.

Referências: [Validação real anterior](phase3-live-retest-20261101.md), [investigação do decoder](phase3-live-vs-offline-decoder-investigation.md), [correção proposta/implantada](phase3-sysmon-event1-chain-fix.md) e [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4).
