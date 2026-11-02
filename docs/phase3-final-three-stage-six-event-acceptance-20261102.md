# Fase 3 — aceite operacional 6/6: Manager → Indexer → Dashboard Discover

**Data da conferência:** 02/11/2026. **Resultado:** seis alertas originais de cinco regras personalizadas do Wazuh 4.14.9 correlacionados com **identidade exata** nas três etapas do pipeline.

## Origem das evidências (três fontes independentes)

1. **Manager:** seis alertas originais dos arquivos de rotação `ossec-alerts-01.json.gz` e `ossec-alerts-02.json`, exportados previamente pelo operador autorizado para `.lab/phase3-manager.jsonl`. A auditoria corrigida havia validado os seis timestamps.
2. **Indexer:** seis documentos retornados por `GET wazuh-alerts-*/_search` no Console OpenSearch autenticado, exportados separadamente como `.lab/phase3-indexer.jsonl`. A comparação Manager → Indexer anterior registrou **6/6** coincidências exatas.
3. **Dashboard Discover:** a sessão autorizada na VM `WindowsServer` abriu `Discover` (não Dev Tools), data view `wazuh-alerts-*`, filtro de `rule.id` para as cinco regras e `agent.id=004`. A busca foi salva como `PHASE3_DISCOVER_SIX_ALERTS_20261102` e retornou **6 hits**. O operador remoto abriu **cada um dos seis documentos** individualmente, selecionou a aba **JSON** do Discover e copiou o JSON original disponibilizado pela interface. Na estação Windows, o material foi reduzido imediatamente **somente aos campos `id`, `rule.id`, `agent.id` e `timestamp` original**, sem armazenar o payload completo.

**Detalhe relevante da terceira fonte:** o recurso `Reporting → Generate CSV` também foi utilizado diretamente no Discover e produziu seis linhas, mas **não incluiu `timestamp`**: seu cabeçalho continha somente `agent.id`, `rule.id` e `id` (com escapes no formato exportado). Esse relatório foi conservado **separadamente**, não foi usado como fonte de horário nem para o aceite. O CSV aceito pelo comparador `.lab/phase3-discover.csv` é uma **projeção privada das seis cópias independentes do JSON disponibilizado pela própria interface Discover**, incluindo seus timestamps originais, e **não** um CSV original do Reporting.

Não foram preenchidos timestamps com base em dados do Manager ou do Indexer. Os registros do Discover foram coletados separadamente, em ordem de visualização, antes da comparação com as duas fontes históricas. A procedência foi observada diretamente durante a operação remota autorizada; o comparador sozinho não pode autenticar essa origem, portanto o campo `operator_discover_provenance_verified=false` em sua saída **não deve ser interpretado como uma afirmação automática de procedência**.

## Identidade exata comprovada

Janela UTC: `2026-11-01T20:00:00Z` a `2026-11-02T00:40:00Z`.

| Regra | Manager | Indexer | Discover | Mesmo evento nas três fontes |
| --- | ---: | ---: | ---: | ---: |
| `110100` — PowerShell | 1 | 1 | 1 | **1/1** |
| `110110` — Rundll32 | 1 | 1 | 1 | **1/1** |
| `110120` — Schtasks | 1 | 1 | 1 | **1/1** |
| `110130` — Registry Run Key | 1 | 1 | 1 | **1/1** |
| `110140` — conta local | 2 | 2 | 2 | **2/2** |
| **Total** | **6** | **6** | **6** | **6/6** |

O programa versionado `scripts/phase3_compare_discover_export.py`, executado **offline**, retornou:
- `manager_indexer_exact_matches = 6`;
- `discover_exact_matches = 6`;
- `discover_export_rows = 6`;
- saída com **código 0** e distribuição correta de todos os cinco IDs.

O comparador exige `id`, `rule.id`, `agent.id` e timestamp normalizado em UTC para cada evento. O operador confirmou separadamente que a fonte do Discover foi a própria interface; por isso, o resultado da etapa é **PASS 6/6**, com a ressalva da projeção privada do JSON descrita acima.

## Segurança, integridade e limites

- Registros originais e projeções privadas estão somente em `.lab/`, ignorado pelo Git; não publicar IDs de alertas, logs, usuários/hosts ou screenshots com detalhes.
- A coleta final foi **somente leitura** do Wazuh; sem novos testes de ataque, reconfiguração de regras, reinicialização de containers, mudança de credenciais ou remoção de registros.
- A verificação trata **exclusivamente os seis alertas da janela UTC acima**. Não corrige nem esclarece automaticamente a **lacuna histórica de indexação entre 27 e 30/10/2026**, que continua investigação independente.
- Alertas do laboratório resultam de **cenários benignos autorizados**; não equivalem a incidentes reais em produção.
- Este aceite é evidência operacional do laboratório, distinta do CI e dos testes sintéticos das regras.

**Decisão:** a Fase 3 de correlação dos cinco cenários personalizados na janela observada está **concluída (6/6 PASS)**. [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4) pode ser encerrada com base nesta evidência delimitada, sem declarar resolvida a lacuna histórica de 27–30/10.

Referências internas: [comparação Manager–Indexer](phase3-manager-indexer-exact-correlation-20261102.md) · [evidência anterior do Discover](phase3-five-rule-dashboard-evidence-20261102.md) · [procedimento de verificação](phase3-discover-csv-acceptance.md).
