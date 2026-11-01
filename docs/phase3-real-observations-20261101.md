# Fase 3 — Evidências reais do Wazuh (01/11/2026)

> **Estado: validação parcial.** Foram confirmados eventos reais no Manager e a correlação Manager → Indexer para uma amostra recente. **Não há comprovação Manager → Indexer → Dashboard, do mesmo evento, para as cinco regras do projeto.** A Issue #4 permanece aberta.

## Escopo e método

Inspeção autorizada e **somente leitura** do laboratório Wazuh Docker **4.14.9** (Kali + Windows), via Desktop Commander → SSH. Dados consultados: arquivos históricos JSON/JSON.GZ do Wazuh Manager, registro persistido do Filebeat e índices `wazuh-alerts-*` do Indexer. A consulta ao Indexer utilizou a autenticação administrativa existente por certificado TLS; nenhuma senha foi publicada.

As ações de recuperação de acesso ao Dashboard foram **anteriores a esta inspeção**: a senha `admin` foi validada no Indexer (HTTP 200), e Manager/Dashboard foram recriados com a configuração atualizada **sem remover volumes**. O Indexer permaneceu no mesmo contêiner. O operador confirmou visualmente o login no Dashboard. **Acessar a interface não prova a presença de um alerta específico nela.**

## 1. Detecções presentes no Manager

Leitura direta dos arquivos preservados em `/var/ossec/logs/alerts/2026/Oct/`:

| Data de arquivo | Regra | Contagem |
| --- | --- | ---: |
| 27/10 | `110110` — rundll32 | 1 |
| 28/10 | `110120` — scheduled task | 1 |
| 28/10 | `110140` — criação de conta local | 4 |
| 30/10 | `110130` — Run Key | 1 |
| 30/10 | `110140` — criação de conta local | 2 |
| **Total** | **4 regras distintas** | **9** |

O arquivo de 29/10 continha **zero** alertas dessas cinco regras. A regra `110100` **não foi encontrada nos arquivos 27–30/10**; sua validação no Manager está descrita no registro histórico de engenharia, mas não há demonstração atual de indexação ou exibição no Dashboard.

Amostra preservada: **9 IDs de evento distintos**, com correspondência individual de arquivo, regra, horário e hashes dos identificadores. Os arquivos originais não foram alterados.

## 2. Evidências no Indexer para esses alertas

Consulta autenticada, somente leitura, com HTTP **200**. Os índices de outubro disponíveis foram:

| Índice (sufixo de data) | Documentos observados |
| --- | ---: |
| `2026.10.21` | 567 |
| `2026.10.22` | 4 |
| `2026.10.23` | 878 |
| `2026.10.24` | 260 |
| `2026.10.25` | 738 |
| `2026.10.26` | 780 |
| `2026.10.31` | 600 |

**Não foram encontrados índices diários 27–30/10** nesse padrão. Uma pesquisa adicional pelas regras `110100`, `110110`, `110120`, `110130` e `110140`, **sem filtro de datas, em todos os `wazuh-alerts-*`**, retornou **0**. Portanto, os nove alertas históricos não foram correlacionados com documentos atualmente pesquisáveis nesse conjunto de índices.

**Limite de inferência:** ausência de documentos/índices agora não demonstra, sozinha, que nunca foram indexados: retenção, remoção de índice, falha de ingestão ou outros fatores são hipóteses ainda não discriminadas.

## 3. Diagnóstico do Filebeat

O processo **Filebeat 7.10.2** estava ativo na inspeção. O registro em `/var/lib/filebeat/registry/filebeat/log.json` continha como fonte única `/var/ossec/logs/alerts/alerts.json`. Contagens de atualizações do registro por dia (UTC) observadas:

| Dia | Atualizações do registro |
| --- | ---: |
| 27/10 | 6 |
| 28/10 | **0** |
| 29/10 | **0** |
| 30/10 | 6 (offset máximo observado = 0) |
| 31/10 | 7 (offset máximo observado = 0) |
| 01/11 | 118 |

A lacuna de atualizações **sugere problema histórico de continuidade**, mas não estabelece sua causa nem prova exatamente quando houve ou deixou de haver envio bem-sucedido. Os logs completos do contêiner anterior não foram confirmados como preservados; não atribuir uma causa raiz sem evidência adicional.

## 4. A integração atual Manager → Indexer funciona

No arquivo `alerts.json` corrente, havia **599 eventos de 01/11/2026** no momento da consulta. Selecionamos os **40 últimos eventos existentes** e pesquisamos seus IDs no Indexer, sem executar simulações:

- Requisição ao Indexer: **HTTP 200**.
- IDs localizados no Indexer: **40/40**.
- Correspondência simultânea de **ID do evento, ID da regra, ID do agente e timestamp**: **40/40**.

**Conclusão válida:** o fluxo **Manager → Indexer** estava operacional para essa amostra real recente. Isso **não recupera** os nove eventos históricos de 27–30/10 e **não confirma** a identidade desses 40 eventos no Dashboard.

### Confirmação visual independente no Discover — 01/11/2026

O operador forneceu uma captura da interface **Wazuh Dashboard → Discover**, com o índice `wazuh-alerts-*` e eventos reais do dia 01/11, incluindo um evento da regra **`5502`** (PAM: sessão encerrada), agente **`005`**, às **16:12:57.746 (America/Sao_Paulo)**. O registro visível inclui o ID de alerta, a regra, o agente, o timestamp e o nome do índice.

Foi realizada uma **nova pesquisa somente leitura diretamente em `/var/ossec/logs/alerts/alerts.json`** para o ID de alerta exibido na captura. Resultado: **exatamente um** evento, com **ID, `rule.id=5502`, `agent.id=005` e timestamp UTC `2026-11-01T19:12:57.746+0000`** correspondentes ao documento mostrado no Discover (conversão de fuso UTC-03:00).

**Conclusão delimitada:** comprovação de **um mesmo evento real de 01/11 no Manager → Indexer → Dashboard**, usando registro original do Manager e a apresentação de documento no Discover, sem criar novos eventos ou alterar o laboratório. Trata-se da regra operacional **`5502`**, **não** das regras personalizadas `110100`–`110140`. Não confundir esta prova adicional com a amostra independente **40/40 Manager→Indexer** ou com a lacuna histórica de **27–30/10**.

A captura recebida do operador **não é publicada** no GitHub por conter IPs internos e dados de agente. O ID original e a identidade completa permanecem somente no laboratório/conversa do operador; o relatório público registra apenas campos mínimos e conclusão sanitizada.

## 5. Integridade e custódia das evidências

O manifesto privado, criado no laboratório em 01/11/2026, está em:

`/home/kali/.local/share/wazuh-evidence/phase3/manager-historical-20261101T190733Z.json`

- Arquivo local protegido por permissão Unix **0600**, diretório **0700**.
- Contém **SHA-256 dos quatro arquivos de origem**, nove registros por regra/horário, e **SHA-256 de IDs de evento e agente**, sem inserir logs brutos neste repositório.
- SHA-256 do manifesto: `44a8d5a432e5c61eb429bb2302dfca92d70428810e57a12846b7d32c01d6432f`.
- Os quatro arquivos de origem permanecem nos volumes do Manager. **Não houve replay, reindexação nem alteração das evidências originais.**

O manifesto **não foi enviado ao GitHub**: permanece privado no laboratório. Hashes auxiliam a rastreabilidade, mas não substituem cadeia de custódia formal nem prova visual independente.

## 6. Decisão e pendências operacionais

| Critério | Situação |
| --- | --- |
| Regras `110110`, `110120`, `110130`, `110140`: alertas em arquivos originais do Manager | **Observado** |
| Regra `110100`: alerta nesta janela histórica disponível | **Não observado** (há registro anterior) |
| Os nove eventos 27–30/10 no Indexer pesquisável | **Não localizado** |
| Manager → Indexer para amostra existente de 01/11 | **Confirmado (40/40)** |
| Mesmo evento recente identificado no Dashboard | **Confirmado: 1 evento da regra 5502 (não é regra personalizada)** |
| Validação end-to-end das cinco regras | **Não concluída** |

**Próximas ações:** (1) buscar evidências retrospectivas de saúde do Filebeat/Indexer e de operações de retenção/exclusão de índices, se existentes; (2) manter a comprovação visual do evento recente da regra **5502** como evidência de disponibilidade ponta a ponta **genérica**, distinta da validação das cinco regras; (3) decidir explicitamente com o operador se eventual reprocessamento histórico será útil, preservando arquivos originais e identificando qualquer dado reindexado como **replay posterior**, jamais como prova de ingestão histórica original; (4) executar o gate de evidências conservador da Fase 3 e manter a Issue #4 aberta enquanto a validação das regras estiver incompleta.

**Segurança:** não publicar credenciais, IPs internos, logs brutos, nomes de agentes ou IDs originais. Não executar novas simulações nem alterar o pipeline de produção para forçar um `PASS`.
