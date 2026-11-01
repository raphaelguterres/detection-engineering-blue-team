# Fase 3 — Investigação forense da lacuna de indexação (01/11/2026)

**Status:** investigação retrospectiva parcial, **causa raiz não comprovada**. Este documento complementa [as observações operacionais reais](phase3-real-observations-20261101.md). Os dados foram consultados no laboratório autorizado, **sem alteração de contêineres, volumes, registros, regras ou índices** nesta inspeção.

## Objetivo e escopo

Determinar se existe evidência que explique a ausência dos índices diários `wazuh-alerts-4.x-2026.10.27` a `2026.10.30`, enquanto os arquivos originais do Wazuh Manager contêm **nove alertas de quatro regras** nesses dias.

Ambiente: Wazuh Docker 4.14.9, Kali, Wazuh Manager, Indexer e Dashboard. Fontes: arquivos históricos do Manager (`*.json` / `*.json.gz`), estado atual do Indexer via API TLS autenticada por certificado administrativo, registro persistido do Filebeat e logs históricos `journalctl -u docker.service` da VM Kali.

## Evidência 1 — eventos históricos do Manager

| Arquivo (outubro 2026) | Regra | Quantidade | Intervalo temporal observado (UTC) |
| --- | --- | ---: | --- |
| 27 | `110110` | 1 | 27/10 18:02:23 |
| 28 | `110120` | 1 | 28/10 01:52:39 |
| 28 | `110140` | 4 | 28/10 15:48:01–15:51:43 |
| 29 | IDs da shortlist | 0 | — |
| 30 | `110130` | 1 | 30/10 18:08:09 |
| 30 | `110140` | 2 | 30/10 18:08:23 |
| **Total** | **4 regras** | **9** | |

Arquivos de origem preservados em `/var/ossec/logs/alerts/2026/Oct/`; inventário privado de IDs e checksums preservado em `/home/kali/.local/share/wazuh-evidence/phase3/`. A regra `110100` não foi localizada nos arquivos desta janela; sua demonstração anterior no Manager permanece no registro histórico de validação.

## Evidência 2 — histórico e estado atual do Indexer

Em consulta somente leitura, o Indexer respondeu **HTTP 200**:

- Estado atual `/_cluster/health`: **green**, um nó.
- Índices de alertas existentes em outubro: dias **21, 22, 23, 24, 25, 26 e 31**, sem índices de 27, 28, 29 ou 30.
- Pesquisa sem filtro temporal pelas cinco IDs `110100`, `110110`, `110120`, `110130`, `110140`, em `wazuh-alerts-*`: **zero** documentos.
- Consulta a `/_plugins/_ism/policies?size=100`: **HTTP 200, zero políticas ISM** cadastradas atualmente.

**Interpretação limitada:** não há evidência de uma política ISM **atualmente configurada** responsável pelo desaparecimento dos índices, mas políticas anteriores podem ter sido removidas e exclusões manuais ou mecanismos externos permanecem possíveis. Ausência atual não prova ausência histórica.

## Evidência 3 — Filebeat e logs do host

- Filebeat **7.10.2** está ativo no Manager.
- O arquivo de registro `/var/lib/filebeat/registry/filebeat/log.json` aponta para a fonte corrente `/var/ossec/logs/alerts/alerts.json`.
- O registro persistido contém **0 atualizações em 28/10 e 29/10**, seis em 27/10 e seis em 30/10, com offset máximo em 30/10 = 0. Isso é compatível com lacuna ou reinicialização de coleta, mas não prova de forma definitiva perda de eventos ou causa raiz.
- A VM manteve logs históricos `journalctl` referentes ao período. No serviço Docker foram observados:
  - **27/10, inicialização:** avisos sobre sandboxes de rede/endereços de serviço ausentes, durante inicialização do daemon.
  - **28/10, por volta de 21:08 UTC:** falhas de resolução DNS externa e mensagens de rede indisponível.
  - **30/10, inicialização:** novos avisos de sandbox de rede inexistente; também falhas de resolução DNS mais tarde, por volta de 21:25 UTC.
- **Correlação temporal importante:** os alertas de 28/10 foram registrados às 01:52 e 15:48–15:51 UTC, *antes* dos erros DNS de 21:08 UTC; os alertas de 30/10 ocorreram por volta de 18:08 UTC, *antes* das falhas DNS de 21:25 UTC. Portanto, esses erros **não explicam diretamente** por si sós o desaparecimento dos índices ou a ausência de ingestão desses eventos.
- O `journalctl -u docker.service` não demonstrou uma causa exclusiva ou erro individual do Filebeat que explique os nove alertas.

**Hipóteses em aberto:** intermitência da ingestão entre Manager e Indexer, períodos de inatividade e reinicialização do Filebeat, exclusão/retenção por mecanismo não identificado, indisponibilidade prévia do Indexer. Não escolher uma hipótese como causa sem evidência específica.

## Evidência 4 — configuração e pipeline recentes

- Os cinco arquivos `detection-engineering-110100.xml`, `-110110.xml`, `-110120.xml`, `-110130.xml` e `-110140.xml` **existem** no Manager, contêm seus respectivos IDs e passaram na validação XML.
- `/var/ossec/bin/wazuh-analysisd -t`: **exit code 0**, sem reinício.
- No relatório anterior, **40/40 alertas existentes de 01/11** tiveram correspondência exata no Manager e no Indexer (ID, regra, agente, timestamp).
- Um alerta da regra operacional **5502** foi confirmado visualmente no Discover e localizado com a mesma identidade no arquivo do Manager. **Não é uma das cinco regras personalizadas.**

**Conclusão operacional:** o pipeline **está funcionando para a amostra recente**, as regras customizadas estão corretamente instaladas e o motor aceita sua configuração. **Não há prova de que os nove alertas históricos estejam/tenham estado no Indexer**, nem de visibilidade das cinco regras no Dashboard.

## Critérios de encerramento e decisão recomendada

| Decisão | Permitido afirmar |
| --- | --- |
| Publicar o estudo de caso e apresentar o projeto no portfólio | **Sim**, com relato transparente dos limites e evidências reais atuais |
| Declarar `Manager → Indexer → Dashboard` funcional para um evento existente da regra 5502 | **Sim**, prova visual e identidade confirmadas |
| Declarar **cinco regras customizadas 5/5 ponta a ponta** | **Não** |
| Declarar **causa raiz da lacuna 27–30/10 identificada** | **Não** |
| Fechar automaticamente a Issue #4 | **Não**; a aceitação operacional específica permanece aberta |
| Reindexar/reenviar arquivos históricos como se fossem ingestão contemporânea | **Não**; qualquer replay futuro requer autorização, preservação dos originais e rótulo explícito de replay posterior |

### Próximas ações seguras

1. Manter manifesto privado e arquivos originais inalterados; preservar snapshots/backup dos volumes antes de qualquer intervenção histórica.
2. Verificar eventual histórico de operação de índices (auditoria, snapshots, jobs externos) **se registros disponíveis**; documentar se forem insuficientes.
3. Separar aceitação de **engenharia de regras** da **comprovação end-to-end das cinco detecções**; não forçar PASS por ausência de evidência.
4. Se o operador optar por uma sessão de reteste, fazer plano de simulações **benignas e autorizadas** com captura simultânea de eventos Manager → Indexer → Dashboard, critérios de rollback, falsos positivos e limpeza. Essa ação não foi executada nesta inspeção.
5. Desenvolver o próximo projeto **Incident Response & SOAR Lab**, mantendo esta Issue como dívida de validação operacional claramente documentada.

**Segurança e privacidade:** não publicar endereços internos, credenciais, identificadores integrais dos agentes, logs brutos ou dados dos endpoints no repositório.
