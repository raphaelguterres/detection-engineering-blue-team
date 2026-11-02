# Fase 3 — encaminhamento da detecção PowerShell pela árvore nativa

**Status:** proposta de ajuste para `110100`, a validar em produção do laboratório separadamente. As duas outras regras corrigidas (`110110` e `110120`) **já têm documentos pós-deploy no Indexer visíveis no Dashboard**. A Issue #4 permanece aberta.

## Evidência no Discover autenticado — 01/11/2026

Consulta visual somente leitura ao data view `wazuh-alerts-*` na VM Windows Server, última janela de 24 horas, agente `004`:

| Filtro `rule.id` | Documentos encontrados | Ocorrência no horário do reteste |
| --- | ---: | --- |
| `110110` | 1 | Rundll32, 15:19:45.738 exibido no navegador |
| `110120` | 1 | Schtasks, 15:19:52.407 exibido no navegador; argumento `/create` e marcador do teste inspecionados no documento |
| `110100` | 0 | Sem alerta personalizado nessa janela |
| `92057 and agent.id:004` | 3 | PowerShell, 15:19:37.962 exibido no navegador, compatível com reteste pós-deploy |

Os horários acima são **os exibidos pela VM**; a fonte Sysmon UTC do reteste é aproximadamente 23:19 UTC. Os documentos `110110` e `110120` estão **indexados e visíveis no Dashboard**. **Ainda não houve comparação independente de identidade exata com `alerts.json`** após o deploy, porque a consulta de logs remotos foi bloqueada. Nenhum evento foi reexecutado para esta pesquisa.

## Competição observada e conteúdo da regra nativa

A regra nativa `92057`, no arquivo `0800-sysmon_id_1.xml` do Wazuh 4.14.9, é nível 12, deriva de `sysmon_event1`, exige `win.eventdata.parentImage` de PowerShell e `win.eventdata.commandLine` com argumento de comando codificado. A regra personalizada `110100` também era nível 12 e derivava diretamente de `sysmon_event1`. No evento benigno do reteste, o resultado ao vivo foi a **nativa `92057`**, não a personalizada.

### Hipóteses avaliadas em cópia descartável

1. **Somente `<if_sid>92057</if_sid>`:** todos os 11 fixtures originais passaram no Wazuh 4.14.9 isolado quando a execução positiva tinha pai PowerShell. Entretanto, acrescentar um caso positivo de PowerShell codificado iniciado por **`cmd.exe`** resultou em **11/12**, pois o evento foi classificado pela base `61603` e a regra customizada deixou de detectar. **Rejeitada** por regressão de cobertura.
2. **`<if_sid>61603,92057</if_sid>`:** o mesmo executor isolado passou em **12/12** com casos positivos de pai PowerShell e de pai `cmd.exe`, caso negativo de administração normal e os positivos/negativos das outras quatro regras. Este é o **candidato proposto**, não um `PASS` live.

A regra continua verificando o provedor Sysmon, Event ID 1, imagem `powershell.exe`/`pwsh.exe` e argumento `-enc`/`-encodedcommand`, conservando ID `110100`, nível e MITRE `T1059.001`. **Não foram modificadas regras nativas**, nem a lógica das outras quatro customizadas.

## Critérios de promoção e rollback

1. Aprovar os testes offline e o workflow CI desta branch. Confirmar que a versão atual do Manager contém os três XML da implantação anterior e que `wazuh-analysisd -t` passa.
2. Criar um **novo backup privado somente do XML `110100` atual**, registrar SHA-256, proprietário, grupo e permissões; verificar novamente antes de alterar. **Não usar rollback do pacote de três regras**: ele removeria as correções já comprovadas de `110110` e `110120`.
3. Aplicar somente o candidato `110100`, validar sintaxe, reiniciar uma vez o Manager e aguardar `analysisd`, `remoted`, Indexer e agente `004` ficarem prontos. Em falha, restaurar o XML original e hash com restart e saúde verificados; se rollback falhar, **parar**.
4. Executar **um único cenário benigno PowerShell** no Windows Server com um marcador novo e verificar a limpeza.
5. Consultar o Discover autenticado, mesmo período e agente: exigir um documento **`110100`** no Indexer/Dashboard; não aceitar apenas a nativa `92057`. Separadamente conferir a identidade do mesmo alerta no Manager por uma via autorizada; se estiver bloqueada, manter o estado como parcial.
6. Preservar `110110`/`110120` e não repetir os testes ou reindexar evidências históricas apenas para obter resultados positivos.

A descoberta e os resultados desta branch estão ligados à [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4). Não publicar marcadores únicos, logs originais, credenciais, IPs ou documentos indexados brutos.
