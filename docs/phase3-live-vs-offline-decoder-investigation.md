# Fase 3 — comparação automatizada: arquivo bruto versus motor de regras

**Data da inspeção:** 01/11/2026. **Escopo:** laboratório Wazuh 4.14.9 autorizado. Relacionado à [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4).

## Descoberta com eventos reais

A auditoria dos três cenários benignos realizados pelo operador encontrou os marcadores no `archives.json` e os campos Sysmon correspondentes. A leitura de metadados (sem divulgação de eventos brutos) mostrou:

| Cenário | Marcadores no arquivo | Sysmon Event ID 1 correspondente | Decoder **ao vivo** | Regra **ao vivo** | Regra via `wazuh-logtest` do `full_log` |
| --- | ---: | ---: | --- | --- | --- |
| PowerShell | 1 | 1 | `windows_eventchannel` | `92057` (nativa) | `110100` (custom) |
| Rundll32 | 1 | 1 | `windows_eventchannel` | **nenhuma** | `110110` (custom) |
| Schtasks | 3 | 2 | `windows_eventchannel` | **nenhuma** | `110120` em **um** dos dois eventos de processo |

**Ponto central:** ao passar `full_log` bruto diretamente para a ferramenta CLI `wazuh-logtest`, o decoder do teste foi `json` nos quatro registros Event ID 1, enquanto o motor em execução usou **`windows_eventchannel`**. O arquivo preservado mostra, portanto, uma **diferença verificável no caminho de decodificação**, além da diferença na decisão final da regra.

Não é correto atribuir toda a divergência ao decoder sem uma prova isolada adicional: diferenças de estado da sessão, hierarquia de regras, precedência de regra nativa e contexto de localização também precisam ser avaliadas. A análise em `wazuh-logtest` não reproduz automaticamente a ingestão integral de um agente Windows.

**Saúde da configuração:** os cinco XML customizados têm mtime anterior à inicialização mais recente do contêiner; o Wazuh registra 8.466 regras habilitadas e EPS limit desativado. Não foi observado indicador suficiente para declarar uma configuração não recarregada ou descarte por limite EPS como causa.

## Automação somente leitura

Implementado em [`scripts/lab/archive_live_vs_logtest.py`](../scripts/lab/archive_live_vs_logtest.py). Faz:

1. Lê o `archives.json` existente, procurando os três marcadores de teste (sem escrever no Manager).
2. Seleciona apenas registros **Sysmon Event ID 1** dos executáveis esperados.
3. Compara o decoder e a regra registrados na ingestão real com o resultado de `wazuh-logtest` **isolado** aplicado ao `full_log` arquivado.
4. Emite somente JSON com contagens, tipos de decoder, regras e divergências. Não imprime evento bruto, marcadores, nomes de usuário, agentes ou conteúdo de comandos.
5. Limita a oito amostras por cenário e não reinicia serviços, não altera arquivos nem envia novos eventos ao SIEM.

### Uso local autorizado na Kali

No clone do repositório, criar um **arquivo privado** `markers.json`, fora do GitHub e do diretório versionado, com os três IDs da execução já realizada:

```json
{
  "powershell": "DE-xxxxxxxxxxxxxxxx",
  "rundll32": "DE-xxxxxxxxxxxxxxxx",
  "schtasks": "DE-xxxxxxxxxxxxxxxx"
}
```

Substituir os valores pelos identificadores reais mantidos pelo operador. Proteja o arquivo com `chmod 600 markers.json`. **Nunca publicar esse arquivo no repositório.**

Rodar a análise dentro do Manager, alimentando o JSON privado por stdin, sem criar arquivos adicionais no contêiner:

```bash
docker exec -i single-node-wazuh.manager-1 python3 -c "$(cat scripts/lab/archive_live_vs_logtest.py)" \
  --archive /var/ossec/logs/archives/archives.json --markers-stdin < markers.json
```

**Interpretação:** `offline_expected_rule_count` > 0 com `live_custom_rule_event_count` = 0 significa **discrepância**, não detecção aprovada. Uma regra customizada é considerada `verified` somente após existir a **mesma identidade de evento** no Manager, Indexer e Dashboard.

## Próximo gate

- Investigar a hierarquia `sysmon_event1` / `windows_eventchannel` nos próprios arquivos de regras do Wazuh (regras de base e nativas) e a configuração de localização do evento.
- Preparar proposta em **branch separada** com `<if_sid>` ou `<if_group>` somente quando houver justificativa comprovada, testes positivos e negativos, análise de sobreposição com `92057` e rollback.
- Em seguida fazer **novo reteste benigno** das três regras, apenas uma vez cada, validando eventos no Manager e Indexer, e conferir o mesmo documento no Discover do Dashboard.
- Preservar a captura já existente, `logall_json=no` e o backup da configuração. **Não repetir captura nem alterar regras no ambiente durante esta auditoria.**

Referências oficiais: [Wazuh — testes de decoders e regras](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html), [Sintaxe de regras / hierarquia `if_group` e `if_sid`](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) e [configuração de coleta EventChannel](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html).
