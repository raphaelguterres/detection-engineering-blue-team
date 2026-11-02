# Fase 3 — validar os seis eventos originais no Dashboard Discover

**Estado:** Manager → Indexer **6/6 comprovado**. O aceite Dashboard Discover **ainda está pendente** até exportar os documentos **da interface Discover** e compará-los independentemente. Esta ferramenta não conecta nas VMs, não usa credenciais e não executa simulações.

## Passo único restante no laboratório

1. Abra a **sessão Wazuh Dashboard → Explore → Discover** autorizada na VM Windows Server. **Não use Dev Tools/Console** nesta etapa.
2. Selecione o data view **`wazuh-alerts-*`** e configure a janela absoluta **2026-11-01T20:00:00Z a 2026-11-02T00:40:00Z**. Na VM com relógio UTC−8, isso equivale ao dia 01/11 das 12h até as 16h40.
3. Com a linguagem **DQL** ativa, filtre:

   ```text
   rule.id: (110100 or 110110 or 110120 or 110130 or 110140) and agent.id: 004
   ```

4. Na tabela do Discover, selecione **somente** as colunas de valor simples **`id`**, **`rule.id`**, **`agent.id`** e **`timestamp`**. O ID de alerta a comparar é **`id`**, não `_id` do documento OpenSearch. São esperadas seis linhas. Certifique-se de que `timestamp` exporte uma string ISO 8601 **com fuso** (UTC `Z`/`+0000` ou offset explícito). Se o aplicativo apresentar apenas horário local sem fuso, não invente o offset; normalize com a evidência original antes de aceitar.
5. Clique **Download as CSV** na página do **Discover**, com os seis documentos visíveis. Em algumas versões a opção é **Reporting → Generate CSV** (pode exigir permissão de relatório). A opção e o layout variam conforme a versão. A [documentação do OpenSearch](https://docs.opensearch.org/latest/dashboards/discover/index-discover/) descreve o procedimento. A exportação deve ser independente do JSON previamente coletado no **Indexer Dev Tools**.
6. Transfira o CSV **diretamente para a estação Windows do repositório**, por um meio autorizado que não envolva enviar evidências ao chat ou publicar na internet, e salve-o como:

   ```text
   C:\Users\rapha\Downloads\detection-engineering-blue-team\.lab\phase3-discover.csv
   ```

7. Na estação Windows, com a versão do repositório atualizada, execute por duplo clique **`scripts\phase3-verify-discover.bat`**. Alternativa por terminal:

   ```powershell
   python scripts/phase3_compare_discover_export.py
   ```

O script lê **somente** os arquivos ignorados pelo Git: Manager, Indexer e CSV do Discover. Ele exige seis identidades exatas pelo mesmo **`id`**, **`rule.id`**, **`agent.id`** e instante UTC normalizado, uma por cada regra `110100`, `110110`, `110120`, `110130` e duas para `110140`.

### Como interpretar a saída

- `discover_exact_matches: 6` e `status: SIX_EXACT_MATCHES_REQUIRES_OPERATOR_PROVENANCE_REVIEW`: as seis identidades correspondem, mas o **operador** precisa confirmar que o CSV foi obtido **independentemente da interface Discover**. Depois da revisão, registrar somente o agregado público `Discover 6/6 confirmado` e atualizar a [Issue #4](https://github.com/raphaelguterres/detection-engineering-blue-team/issues/4) e o roadmap do perfil.
- `NOT_ACCEPTED_INCOMPLETE_OR_MISMATCH` ou `DISCOVER_COMPARISON_UNAVAILABLE_OR_INVALID_EXPORT`: ainda **não** há aceite. Revisar o filtro, o tempo, as colunas e o formato da exportação, sem repetir cenários ou alterar a infraestrutura.

**Nenhuma saída contém IDs reais**, credenciais ou linhas brutas. Não anexe o CSV, os logs ou imagens com identificadores pessoais ao GitHub. A ferramenta não autentica a origem do arquivo por si só; a confirmação da procedência é obrigatória.

O milestone **M0** em [roadmap do perfil](https://github.com/raphaelguterres/raphaelguterres/blob/main/roadmaps/PROGRESSO.md) e a Issue #4 só podem ser encerrados **após** a confirmação independente da origem e das seis identidades. A lacuna histórica de 27–30/10 continua fora desse aceite.

> Referência: [OpenSearch — Exportar dados do Discover](https://docs.opensearch.org/latest/dashboards/exporting-data/).
