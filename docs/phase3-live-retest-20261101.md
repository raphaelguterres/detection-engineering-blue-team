# Fase 3 — Reteste operacional controlado das cinco detecções (01/11/2026)

> **Resultado: cinco execuções benignas com telemetria local; duas das cinco regras customizadas confirmadas no Manager e correlacionadas por identidade no Indexer. Nenhuma das cinco obteve aprovação integral no Dashboard nesta sessão.** Não apresentar isso como “5/5 end-to-end”.

## Contexto e autorização

Reteste em laboratório **VirtualBox isolado e autorizado**, com Windows Server 2022 (agente Wazuh **004**) e Wazuh Manager/Indexer/Dashboard Docker **4.14.9** na Kali. O acesso SSH Kali e a integração Wazuh estavam funcionais. O WinRM respondeu ao diagnóstico, mas recusou sessão autenticada com as credenciais apresentadas; portanto **não foi usado para executar testes**.

Foi usado o **`scripts/lab/windows-worker.ps1` versionado no GitHub** por meio de uma janela administrativa já autorizada **dentro da VM**, acionada pela console gráfica do VirtualBox. O invólucro local conferiu o nome do endpoint, privilégios de administrador e retornos de cada cenário. O teste não usou malware, exploits ou credenciais reais; cada execução teve identificador único, não publicado aqui.

**Evidência histórica prévia** de cinco alertas no Manager está em [Validação operacional registrada](operational-validation.md); os resultados abaixo são **novas execuções independentes**, não replays dos eventos de outubro.

## Resultado das execuções

| Regra | Cenário benigno | Sysmon local | Limpeza | Manager: regra específica | Indexer: mesma identidade |
| --- | --- | --- | --- | ---: | ---: |
| `110100` | PowerShell `-EncodedCommand` imprimindo marcador fixo | **Encontrado** (Event ID 1) | Não necessária | **0** | **0** |
| `110110` | Rundll32 com DLL inexistente em caminho gravável | **Encontrado** (Event ID 1) | Não necessária | **0** | **0** |
| `110120` | Criação de tarefa temporária `ONSTART`, sem executá-la | **Encontrado** (Event ID 1) | **Verificada** | **0** | **0** |
| `110130` | Valor temporário HKCU Run com comando `echo` | **Encontrado** (Event ID 13) | **Verificada** | **1** | **1** |
| `110140` | Conta temporária desabilitada e tentativa de duplicação via `net user` | **Encontrado** (Event ID 1) | **Verificada** | **2** | **2** |

As cinco execuções retornaram **`LOCAL_TEST_STATUS=PASS`**, conferidas na janela da própria VM. Para os três cenários que criaram artefatos, o `windows-worker.ps1` executou limpeza e relatou `cleanup=verified`.

### Checagem independente de limpeza

Uma segunda inspeção **somente leitura**, depois dos cinco testes, pesquisou artefatos temporários com os padrões exclusivos do executor no Windows Server. Resultados:

- Tarefas temporárias restantes: **0**.
- Valores temporários em HKCU Run restantes: **0**.
- Contas locais temporárias restantes: **0**.
- `CLEANUP_INDEPENDENTLY_VERIFIED=YES`.

A verificação independente fortalece o resultado, mas não deve ser generalizada para artefatos fora dos padrões definidos.

## Manager → Indexer: correlação de eventos novos

Consulta ao Indexer autenticada com certificados administrativos existentes, API respondendo **HTTP 200**, sem modificar índices ou documentos. Para as regras `110130` e `110140`, o mesmo **ID de evento, regra, agente e timestamp** foi comparado entre `alerts.json` do Manager e o documento indexado:

| Regra | Alertas Manager | Correspondências exatas no Indexer |
| --- | ---: | ---: |
| `110130` | 1 | **1/1** |
| `110140` | 2 | **2/2** |

### Sobre os três cenários restantes

- **`110100`:** o evento Sysmon chegou ao Manager e produziu **um alerta nativo `92057`**, confirmado também no Indexer com identidade exata. A regra customizada **`110100` não foi acionada ao vivo** nesta execução. O teste offline `wazuh-logtest` com os dados do mesmo evento retornou `110100`, demonstrando uma **divergência entre o caminho de teste e o processamento ao vivo**; isso não identifica sozinho a causa.
- **`110110` e `110120`:** os eventos Sysmon apareceram no endpoint, mas **não foram localizados com os marcadores dos testes em `alerts.json`** do Manager. O `wazuh-logtest` com eventos sintéticos específicos retornou respectivamente `110110` e `110120`. Sem coleta bruta integral e comparação ao vivo, **não atribuir causa específica** à regra, ao agente ou à priorização do motor.
- O fato de um alerta nativo existir **não substitui** o resultado exigido da regra customizada.

Os arquivos XML das cinco regras já haviam sido verificados, e `wazuh-analysisd -t` terminou com código 0. Isso confirma validade sintática, **não aceitação operacional**.

## Dashboard e fronteira de evidências

Após a nova rodada, a abertura direta de **Discover** na VM redirecionou para a página de login. Portanto **não foi realizada comprovação visual do mesmo evento customizado** no Dashboard nesta sessão. A comprovação anterior de um evento **genérico `5502`** permanece válida e é independente.

**Classificação atual desta rodada:**
- **5/5** simulações benignas com Sysmon local encontrado.
- **2/5** regras customizadas com alertas confirmados no Manager e identidades iguais no Indexer.
- **0/5** regras customizadas com correlação completa Manager → Indexer → Dashboard nesta rodada.

Não alterar os resultados do gate oficial para mostrar `verified` até cada regra possuir prova própria nas três etapas.

## Custódia e ações executadas

Manifesto privado desta rodada:

`/home/kali/.local/share/wazuh-evidence/phase3/live-retest-20261101T211517Z.json`

- Permissão restrita **0600** e diretório privado **0700**.
- Registra resultados por regra, integridade por SHA-256 e identificadores **hashados**; não publica eventos brutos, IPs internos, nomes de máquina, senhas ou screenshots.
- SHA-256 do manifesto: `7c203e282716cdd260912726cad59c38e81d14d768fab2c078a22c040edeeb5d`.
- Testes locais criaram somente os artefatos benignos previstos e realizaram limpeza. **Nenhum índice, credencial, arquivo histórico, regra instalada ou configuração Wazuh foi alterado.** Não houve restart do Wazuh nem reprocessamento do arquivo histórico.

## Próximos critérios para fechar a Issue #4

1. Investigar e corrigir, em branch separada com fixtures e **rollback**, a divergência de regra `110100` (nativa `92057` no processamento real) e a ausência de alertas `110110` e `110120`, sem suprimir regras nativas nem gerar `PASS` artificial. Considerar as regras hierárquicas de Sysmon e validar a correspondência dos campos reais recebidos.
2. Executar de novo **apenas os cenários incompletos**, respeitando isolamento e limpeza. Exigir alerta customizado no Manager e mesma identidade no Indexer.
3. Com login autorizado na interface, conferir **cada ID exato** no Dashboard Discover na janela de tempo adequada, preservando registros privados.
4. Atualizar estudo de caso, executar testes offline/CI e manter a dívida técnica histórica de **27–30/10** separada dos resultados desta rodada.

**Decisão:** o projeto pode ser apresentado em portfólio com ressalvas comprovadas; a **aceitação ponta a ponta das cinco regras segue pendente**, e a Issue #4 deve permanecer aberta.
