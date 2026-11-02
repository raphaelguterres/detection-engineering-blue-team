# Fase 3 — auditoria agregada dos arquivos do Manager (somente leitura)

**Objetivo:** identificar por que a busca manual de 01–02/11/2026 retornou contagens vazias, embora seis documentos de cinco regras personalizadas tenham sido observados anteriormente em `wazuh-alerts-*`.

Este script **não exporta alertas**, não faz conexão, não acessa credenciais e não promove a fase a `verified`. Sua saída contém somente nomes de arquivo, contagens por ID de regra e limites de timestamps UTC.

## Fontes observadas no laboratório

A listagem realizada pelo operador dentro do contêiner Wazuh Manager 4.14.9 registrou:

- `/var/ossec/logs/alerts/2026/Nov/ossec-alerts-01.json.gz` — arquivo rotacionado do dia 01.
- `/var/ossec/logs/alerts/2026/Nov/ossec-alerts-02.json` — arquivo corrente do dia 02.
- `/var/ossec/logs/alerts/alerts.json` — arquivo corrente, aparentemente com o mesmo tamanho do arquivo diário do dia 02.

**Evitar contar simultaneamente `alerts.json` e `ossec-alerts-02.json`**, que podem conter os mesmos registros. Não deduzir perda definitiva de dados pelo resultado vazio: verificar as contagens sem janela e possíveis erros de timestamp.

## Execução autorizada

A ferramenta deve estar disponível no **próprio ambiente autorizado** com acesso de leitura aos dois arquivos. O arquivo versionado é `scripts/phase3_manager_archive_audit.py`. Ele não deve ser usado para contornar controles de acesso remoto.

```bash
python3 scripts/phase3_manager_archive_audit.py \
  --file /var/ossec/logs/alerts/2026/Nov/ossec-alerts-01.json.gz \
  --file /var/ossec/logs/alerts/2026/Nov/ossec-alerts-02.json \
  --start-utc 2026-11-01T20:00:00Z \
  --end-utc 2026-11-02T00:40:00Z
```

O comando acima pressupõe que o script está acessível no mesmo ambiente que os arquivos: **não** funcionará no Windows host sem disponibilizar o caminho dos arquivos por método autorizado.

### Como interpretar

- `custom_rules_without_time_filter` positivo, mas `custom_rules_in_window` zero: conferir timestamps originais, rotação e fuso.
- Ambos zero: não há IDs correspondentes nos dois arquivos inspecionados; conferir fontes/retention e os documentos independentes do Indexer sem concluir causa raiz.
- `invalid_json_or_object` positivo em arquivo corrente: pode indicar registro parcial, mas não comprova corrupção de todo o arquivo.
- `missing_or_invalid_timestamp_for_target_rule` positivo: corrigir o diagnóstico temporal, não modificar as fontes.
- Mesmo com eventos encontrados no Manager, **ainda são necessárias exportações originais e independentes do Manager e Indexer**, seguidas do comparador offline e conferência do *mesmo* evento no Discover.

As fontes, IDs completos, nomes de agentes e timestamps por evento devem ficar privados. Publicar somente agregados e a conclusão delimitada na [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4).

**Não reiniciar, alterar regras, ativar logall, repetir simulações, reindexar dados nem desabilitar TLS para obter o resultado esperado.**
