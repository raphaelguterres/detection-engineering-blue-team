# Fase 3 — proposta de correção da hierarquia Sysmon Event ID 1

**Estado:** alteração proposta em branch separada, **não instalada no Manager de produção do laboratório**. O fato de o CI passar não prova que uma regra em execução produziu alerta no Manager/Indexer/Dashboard.

## Diagnóstico reproduzido com eventos reais

Em 01/11/2026, os marcadores do reteste benigno foram encontrados em `/var/ossec/logs/archives/archives.json`, com `Microsoft-Windows-Sysmon`, Event ID **1**, executáveis e argumentos corretos. A decisão real do Manager foi:

| Regra customizada | Processamento live da execução | Teste isolado do mesmo `full_log` |
| --- | --- | --- |
| `110100` PowerShell EncodedCommand | regra **92057**, não a `110100` | `110100` |
| `110110` Rundll32 em caminho gravável | sem alerta customizado | `110110` |
| `110120` Schtasks `/create` | sem alerta customizado | `110120` em 1 dos 2 eventos de processo |

O decoder live é **`windows_eventchannel`**, enquanto o `wazuh-logtest` direto do JSON arquivado selecionou **`json`**. Não inferir que a regra isolada garantidamente funciona ao vivo.

## Hipótese sustentada pela árvore de regras

A regra nativa `61603`, de nível zero, é base para eventos Sysmon Event ID 1 e define o grupo **`sysmon_event1`**. Outras regras nativas, incluindo a `92057`, dependem desse grupo. A regra customizada `110140` com `<if_group>sysmon_event1</if_group>` produziu alertas reais no Manager e Indexer na sessão anterior.

As regras customizadas `110100`, `110110` e `110120` não tinham o vínculo com esse grupo. A **alteração mínima proposta** é adicionar essa dependência às três, preservando IDs, níveis, filtros de processo, expressões dos argumentos e MITRE ATT&CK. É **hipótese plausível a validar**, não causa raiz já comprovada.

Também existe sobreposição da `110100` com a regra nativa **92057**, cuja seleção ainda precisa ser observada depois da mudança. **Não** desativar nem enfraquecer regras nativas para forçar aprovação.

Referências: [Wazuh, sintaxe de `if_group`](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html), [Wazuh, exemplo oficial para Sysmon Event ID 1](https://wazuh.com/blog/learn-to-detect-threats-on-windows-by-monitoring-sysmon-events/).

## Regressões sem tocar na stack ativa

O código `scripts/lab/manager-worker.py` passou a usar a função de **árvore descartável** `windows_replay_config` e `wazuh-logtest-legacy -c <configuração isolada>` para **as cinco IDs** `110100`, `110110`, `110120`, `110130`, `110140`, sem apontar os testes para `/var/ossec/etc/ossec.conf` ativo. O arquivo de configuração e os XML reais não são alterados por essa rotina.

`tests/test_sysmon_event1_rule_chain.py` valida: vínculo com `sysmon_event1`, integridade de IDs e MITRE, fixture positivo/negativo, exclusão de provedor ou Event ID incorretos, preservação das duas regras que funcionaram e encaminhamento de regressão para a árvore isolada.

Rodar no clone do GitHub:

```bash
python3 scripts/quality_gate.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Esses testes de CI são verificações de **contrato e lógica offline**, não equivalem a uma confirmação real da stack. Após CI, a execução de regressão **com o Wazuh 4.14.9** em configuração descartável será o gate técnico seguinte. Não implantar alterações apenas porque fixtures simuladas passaram.

## Plano de promoção seguro (não executado)

1. Validar `main` e o PR (CI aprovado, revisão de diff e CodeRabbit se aplicável). Registrar SHA do commit candidato.
2. Fazer pré-flight no Manager: `wazuh-analysisd -t`, `wazuh-control status`, inventário dos IDs customizados e hashes SHA-256 dos **cinco** arquivos instalados, sobretudo os três a modificar. Preservar backups **privados**, com permissões restritas e cópias fora do volume ativo.
3. Executar os dez fixtures (positivo e benigno para cada uma das cinco regras) em cópia descartável da árvore do Wazuh real, usando o executor existente. Se houver falha, **não** implantar.
4. Implantar **somente as três mudanças** por uma operação auditável que preserve os dois outros XML; o worker de deploy versionado recebe um pacote de cinco regras, cria backup identificado, valida e faz rollback em erro. Revisar as cinco entradas antes de autorizar esse caminho.
5. Validar `wazuh-analysisd -t` **antes** de reiniciar o Manager; após reinício controlado, verificar saúde, endpoints, agentes, Filebeat e indexação.
6. Repetir **somente os três cenários benignos** no Windows Server isolado. Exigir um evento com **mesma identidade** por regra no Manager e Indexer e, após login, o **mesmo evento no Discover**. Registrar limpeza do Windows Server.
7. Se houver regressão, alerta ausente, sobreposição indevida ou indisponibilidade, restaurar os três XML originais com seus hashes, validar configuração e reiniciar o Manager novamente. Não marcar `PASS` sem correlação real.

## Critérios de aceitação

- `110100`, `110110` e `110120`: uma regra **customizada** disparada no Manager por cenário benigno, sem depender de alerta nativo como substituto.
- Identidade idêntica em Manager → Indexer → Dashboard (ID do evento, regra, agente, timestamp); a UI requer conferência visual independente.
- Os casos benignos negativos não devem disparar as regras.
- Regras `110130` e `110140` continuam funcionais, sem alteração do XML.
- Limpeza de artefatos temporários no Windows validada, sem exposição de credenciais ou publicação de eventos brutos.
- Sem replay retroativo dos arquivos 27–30/10 como evidência contemporânea.

A [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4) permanece aberta até a aceitação real.
