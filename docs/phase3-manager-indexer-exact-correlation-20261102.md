# Fase 3 — correlação real de seis alertas Manager → Indexer (02/11/2026)

**Resultado:** **6/6 alertas correlacionados por identidade exata**, abrangendo **5/5 regras de detecção Wazuh personalizadas**. Evidência produzida pelo operador autorizado, em laboratório isolado, sem simulação ou reinício de serviços nesta rodada.

## Procedência independente

- **Manager:** exportação privada dos registros originais de `ossec-alerts-01.json.gz` (cinco eventos de 01/11) e `ossec-alerts-02.json` (um evento de 02/11), dentro do contêiner Wazuh Manager 4.14.9. O arquivo `.lab/phase3-manager.jsonl` foi importado por SCP do diretório privado da Kali e validado previamente como 6/6. O diagnóstico corrigido retornou **6/6 eventos na janela UTC**, com zero erros de parsing.
- **Indexer:** consulta autenticada, independente e exclusivamente de leitura **`GET wazuh-alerts-*/_search`**, executada pelo operador no OpenSearch Console do Wazuh Dashboard. Resposta com `hits.total.value=6`, `timed_out=false`, **27 shards bem-sucedidos / 0 falhas**, e campos projetados `id`, `rule.id`, `agent.id` e `timestamp`. Resposta armazenada somente em `.lab/phase3-indexer-response.json` e convertida localmente em `.lab/phase3-indexer.jsonl`.
- **Comparador:** `FASE3_COMPLETA.bat` privado executado pelo operador na máquina Windows. Comparou as identidades originais independentes, usando `id`, `rule.id`, `agent.id` e instante UTC normalizado (incluindo milissegundos). Relatório e checklist conservados **somente na pasta privada `.lab/`**, ignorada pelo Git. Os dados brutos e os IDs completos não são publicados aqui.

## Resultado obtido

| Regra | Manager | Indexer | Mesma identidade |
| --- | ---: | ---: | ---: |
| `110100` — PowerShell | 1 | 1 | **1/1** |
| `110110` — Rundll32 | 1 | 1 | **1/1** |
| `110120` — Schtasks | 1 | 1 | **1/1** |
| `110130` — Registry Run Key | 1 | 1 | **1/1** |
| `110140` — Local Account | 2 | 2 | **2/2** |
| **Total** | **6** | **6** | **6/6** |

Janela verificada: **2026-11-01T20:00:00Z a 2026-11-02T00:40:00Z**. Agente dos seis documentos do Indexer: `004`.

A saída do operador confirmou literalmente o agregado `MATCHES EXATOS MANAGER x INDEXER: 6/6`, sem divergências por regra. A infraestrutura do laboratório não foi modificada durante a correlação.

## Limite do resultado — Dashboard Discover

A consulta foi executada no **Console/OpenSearch Dev Tools** dentro do Wazuh Dashboard. Isso comprova a existência dos seis documentos no **Indexer**, mas **não substitui a conferência separada de identidade em Discover**.

**Pendente:** para cada uma das seis linhas do arquivo privado `.lab/phase3-dashboard-checklist-*.csv`, usar a sessão autenticada do Dashboard **Discover** e confirmar a identidade do mesmo documento — **`id`, `rule.id`, `agent.id` e `timestamp`**. Se o Discover exibir fuso local, converter para UTC antes de comparar. Registre localmente seis confirmações ou a divergência encontrada. Não é necessário repetir simulações, reindexar ou desativar a verificação TLS.

O aceite da Fase 3 está **Manager→Indexer: PASS (6/6)**; **Manager→Indexer→Dashboard Discover: PENDENTE**. A [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4) permanece aberta.

## Escopo e ressalvas

O resultado é limitado aos seis alertas desse período; **não prova** que a lacuna histórica de indexação de 27–30/10 tenha sido resolvida. Os testes de código e o CI são evidências independentes de qualidade de implementação, não substitutos para os alertas observados no SIEM.
