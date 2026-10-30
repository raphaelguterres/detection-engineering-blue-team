# Automação remota do laboratório

O executor em `scripts/lab/run.py` coordena o Wazuh via SSH/Docker e o endpoint via WinRM. O Wazuh continua sendo a interface operacional. O Git mantém regras, código, contratos e documentação; os relatórios das execuções ficam em `.lab/`, ignorado pelo Git.

## Estado em 28/10/2026

- As duas VMs estavam ligadas, com Guest Additions.
- O SSH do Kali respondeu na rede do lab. A tentativa com verificação estrita parou porque a chave do host ainda não estava reconhecida no host controlador. Isso **não confirma** autenticação do usuário.
- O WinRM HTTP do Windows respondeu à consulta de identificação. A tentativa de sessão com a identidade atual falhou com `ExplicitCredentialsRequired`: a política atual não permite credenciais implícitas via Negotiate/HTTP para esse destino. Uma sessão autenticada ainda não foi confirmada.
- O conector Desktop Commander estava offline.
- Os scripts passaram em testes locais de lógica e sintaxe. **Ainda não houve execução deste novo pipeline nas VMs.**

O commit `909247b` foi publicado e o [CI correspondente](https://github.com/raphaelguterres/detection-engineering-blue-team/actions/runs/40805456207) concluiu com sucesso: 18 testes offline, quality gate e sintaxe Windows PowerShell. Em uma verificação posterior, ambas as VMs estavam em estado salvo e foram retomadas com sucesso. O Kali apresentou tela de desbloqueio, impedindo continuar a conferência da identidade SSH pela sessão gráfica. Próximo ponto de retomada: desbloquear o Kali, conferir a chave do host e concluir autenticação SSH/WinRM antes do primeiro preflight remoto.

O acesso existente pode dispensar instalação de serviços. Faltam a verificação da identidade SSH, uma autenticação autorizada e o inventário local preenchido. Não é preciso trocar de modelo para executar os scripts.

### Retomada em 29/10/2026

As duas VMs foram confirmadas em execução. O Kali estava desbloqueado, com terminal root aberto. A tentativa de inserir a consulta somente de leitura `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` pelo controle gráfico retornou `Acesso negado (0x80070005)`. Uma nova observação confirmou que o comando não foi inserido. A causa do erro de entrada não foi determinada; não há evidência suficiente para atribuí-lo a uma diferença de elevação entre os aplicativos.

O desbloqueio da sessão foi resolvido, mas a verificação da identidade SSH e a autenticação seguem pendentes. A próxima ação depende de restaurar a entrada pelo controle gráfico ou disponibilizar um canal remoto já autenticado. Nenhum novo teste operacional foi executado nesta retomada.

### Conectividade — retomada em 29/10/2026

As janelas de ambas as VMs estavam abertas. A porta TCP 22 do Kali respondeu, mas a conexão SSH com `StrictHostKeyChecking=yes` parou porque a chave ED25519 desse endereço não está cadastrada no `known_hosts`. Não aprovei automaticamente uma chave recebida pela rede.

A porta WinRM 5985 no endereço previamente observado do Windows não respondeu nesta tentativa; não houve sessão nem comando enviado ao Windows. `VBoxManage list runningvms` e a consulta de vizinhos via CIM também retornaram `E_ACCESSDENIED`. A entrada de comandos na janela do Kali não pôde ser confirmada, então não houve preflight, alteração de regra ou simulação.

## Pré-requisitos

No controlador Windows: Python 3.10+, Windows PowerShell 5.1 e OpenSSH Client. No Kali: SSH autenticado por chave e permissão para `docker exec` no container correto, sem prompt de senha. No container: Python 3.10+; o exemplo usa `/var/ossec/framework/python/bin/python3` e esse caminho precisa ser confirmado.

No endpoint: WinRM autenticado, Sysmon e WazuhSvc ativos, canal `Microsoft-Windows-Sysmon/Operational` habilitado e coletado pelo agente. A conta remota deve ter os direitos necessários às simulações. A simulação de conta local recusa controladores de domínio.

O executor não configura firewall, TrustedHosts, WinRM, SSH, Sysmon ou credenciais. Essas configurações pertencem ao laboratório complementar. Especialmente para Event ID 13, preserve e revise a configuração atual do Sysmon antes de aplicar mudanças; ausência de eventos recentes não prova, por si só, que uma categoria está desabilitada.

## Inventário e autenticação

Copie `scripts/lab/config.example.json` para `.lab/config.json` e substitua os campos `REPLACE_`:

| Campo | Uso |
| --- | --- |
| `manager.ssh_target` | Usuário e host ou alias SSH verificado do Kali |
| `manager.container` | Nome/ID confirmado do Wazuh Manager |
| `manager.python` | Python existente dentro do container |
| `manager.agent_id` | Agente Wazuh exato do endpoint de teste |
| `windows.computer_name` | Destino WinRM autorizado |
| `windows.expected_hostname` | Valor real de `COMPUTERNAME`, conferido antes de qualquer simulação |
| `windows.use_ssl` | `true` para HTTPS; `false` somente quando HTTP com autenticação Negotiate/Kerberos estiver configurado no lab |
| `windows.credential_path` | Caminho de uma PSCredential exportada com DPAPI; vazio usa a identidade atual |

Confirme a impressão digital SSH por um canal confiável antes de registrá-la em `known_hosts`. O executor exige `StrictHostKeyChecking=yes` e `BatchMode=yes`; não aceita senhas por linha de comando nem aceita uma chave desconhecida automaticamente.

A credencial WinRM, se necessária, deve ser preparada no controlador pelo mesmo usuário que executará o script, usando `Get-Credential | Export-Clixml` em arquivo privado fora do Git. `Import-Clixml` usa a proteção DPAPI vinculada ao usuário e à máquina. Não envie a senha no chat. Autenticação por IP em um workgroup pode exigir HTTPS ou um TrustedHosts restrito já configurado; o executor não altera essa política.

## Execução

Sem argumentos, o executor apenas mostra o plano e não acessa as VMs:

```powershell
python scripts/lab/run.py plan
```

Com o acesso configurado, uma chamada coordena preflight, instalação, regressão no Wazuh e simulações:

```powershell
python scripts/lab/run.py pipeline --config .lab/config.json
```

A criação de conta fica fora da seleção padrão. Para incluir a simulação autorizada de conta local temporária desabilitada:

```powershell
python scripts/lab/run.py pipeline --config .lab/config.json --include-account
```

Também existem etapas separadas: `preflight`, `deploy`, `replay`, `run`. Exemplo de repetição apenas da Run Key:

```powershell
python scripts/lab/run.py run --scenario runkey --config .lab/config.json
```

O processo retorna `0` quando a etapa selecionada passa e `2` quando há falha ou bloqueio. Sucesso em `plan`, `preflight` ou `replay` não equivale a detecção operacional ponta a ponta.

## Comportamento e limpeza

| Cenário | Ação benigna | Limpeza |
| --- | --- | --- |
| PowerShell | `EncodedCommand` que escreve o identificador do teste | Sem artefato persistente |
| Rundll32 | Caminho único de DLL inexistente em `C:\Users\Public` | Encerra apenas o processo filho se o erro de módulo mantiver a janela aberta |
| Schtasks | Tarefa `ONSTART` com `echo`, sem executar ou reiniciar a VM | Remove e confirma ausência no mesmo fluxo |
| Run Key | Valor único HKCU com `echo` | Remove e confirma ausência em `finally` |
| Conta local | `net user` com nome único, senha aleatória por stdin e `/active:no` | Remove e confirma ausência em `finally`; não adiciona grupos |

A automação usa nomes únicos em vez do nome fixo das simulações manuais. A tarefa automática é `ONSTART` para evitar diferenças de formato de data; não reinicie a VM durante o teste. O HKCU é o da **conta WinRM**, que pode ser diferente da sessão gráfica. A conta temporária depende de direitos administrativos e da política local; falha do comando interrompe o fluxo e não é considerada sucesso. A senha não é argumento de processo nem campo de relatório.

`finally` permite limpeza quando o script continua executando, mas não garante recuperação após desligamento da VM ou interrupção abrupta do processo. Estado desconhecido é registrado como falha e exige recuperação antes de repetir.

## Evidência e interpretação

Cada cenário recebe um identificador aleatório. A confirmação exige simultaneamente: execução concluída, limpeza confirmada, evento Sysmon local e alerta da regra correta para o agente configurado com o marcador daquele teste e o nível definido no XML versionado. Para PowerShell, o marcador é o próprio conteúdo codificado na linha de comando.

O coletor lê até os últimos 8 MiB do `alerts.json` atual e devolve contagens e níveis, sem logs brutos. Não consulta arquivos rotacionados nem garante captura sob volume extremo; `scan_truncated` indica leitura parcial. Um alerta ausente dentro da janela significa `alert_missing`, não uma prova definitiva de ausência na plataforma inteira. `telemetry_missing` indica que o evento local não foi observado. O tempo de espera de alertas é configurável entre 5 e 300 segundos, além dos limites de conexão de cada chamada.

Os arquivos `.lab/runs/<id>/report.json` e `report.md` guardam o resultado. `.lab/journal/<id>/report.json` registra a intenção antes de cada simulação para recuperação de execução interrompida. Nenhum desses diretórios entra no Git; revise manualmente qualquer evidência que venha a publicar.

## Instalação e rollback

`deploy` roda o quality gate local, detecta duplicidades e preserva o nome do arquivo remoto que já contém cada regra. Recusa arquivos compartilhados com outras regras. Salva os conteúdos anteriores e hashes em `/var/ossec/backup/detection-engineering/<id>/manifest.json`, com acesso restrito. A validação `wazuh-analysisd -t` precede o reinício; falha durante a instalação tenta restaurar as alterações desta execução.

O `pipeline` executa os fixtures positivos e negativos usando **wazuh-logtest real** após instalar. Falha nessa regressão solicita rollback do backup criado. Já a falta de telemetria no endpoint interrompe a aprovação operacional, sem atribuir automaticamente a falha ao XML instalado.

Rollback explícito:

```powershell
python scripts/lab/run.py rollback --backup-id DE-0123456789abcdef
```

Use o ID real do relatório. Antes de restaurar, todos os hashes são comparados: mudanças externas posteriores bloqueiam a restauração para preservar o trabalho de outro operador. O backup fica no container; sua persistência depende do volume ou backup do laboratório. O lock `var/run/detection-engineering.lock` impede duas instalações simultâneas deste executor. Se uma instalação for interrompida, inspecione o estado e o backup antes de remover um lock residual. Outras ferramentas não respeitam esse lock: não edite regras simultaneamente.

Recuperação de artefatos de uma simulação registrada:

```powershell
python scripts/lab/run.py cleanup --recovery-id DE-0123456789abcdef --scenario runkey
```

O ID é o da execução principal, presente em `runs` ou `journal`; o executor busca o nome exato daquele cenário. Depois de uma interrupção sem resultado, confirme a propriedade do artefato antes da recuperação. Relatórios que registram colisão de nome são recusados.

## CI e limites da verificação

O GitHub Actions roda o quality gate, testes offline de falhas/correlação/rollback e validação sintática em Windows PowerShell. Não recebe credenciais do lab nem acessa VMs privadas. Os testes mockados não certificam WinRM, Sysmon, compatibilidade do `net user` com stdin, permissões Docker ou comportamento real do Wazuh. Essas verificações permanecem pendentes até uma execução autenticada.

Referências: [Wazuh — regras customizadas](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html), [wazuh-analysisd -t](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html), [Microsoft — Import-Clixml e DPAPI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/import-clixml).

## Retomada remota — 29/10/2026

O operador autorizou uma chave SSH exclusiva do projeto para acesso sem interação ao Kali. A chave pública foi adicionada a `/home/kali/.ssh/authorized_keys` com a opção OpenSSH `restrict` e origem limitada ao host controlador `192.168.56.1`; não habilita encaminhamentos. A chave privada e o `known_hosts` ficam em `.lab/`, ignorados pelo Git, com ACL privada na chave. A identidade ED25519 foi lida diretamente da VM e conferida antes de configurar `StrictHostKeyChecking=yes`. A autenticação SSH por chave foi confirmada sem prompt.

O executor aceita `manager.identity_file` e `manager.known_hosts_file` locais, restritos a arquivos existentes dentro de `.lab/`. `deploy`, `replay` e `rollback` não exigem inventário WinRM. O template versionado documenta os campos.

O probe encontrou o Manager ativo, as cinco regras sem duplicidade e `logall_json=no`. O deploy `DE-2887c78576864e6f` instalou as cinco regras, salvou backup no Manager, passou por `wazuh-analysisd -t` e reiniciou o serviço. O ID de rollback é `DE-2887c78576864e6f`.

A primeira regressão revelou que os fixtures JSON eram decodificados pelo `wazuh-logtest` como `json`, portanto não recebiam o grupo interno `sysmon_event1`/`sysmon_event_13` exigido pelas regras. As condições foram expressas diretamente pelos campos `win.system.providerName` e `win.system.eventID`, mantendo o escopo Sysmon e permitindo testar os eventos registrados. Após novo deploy, o replay `DE-f89a2766e5e94295` passou nos dez casos: cinco positivos nas regras esperadas e cinco negativos sem match indevido. Os relatórios detalhados permanecem em `.lab/runs/`, ignorado pelo Git.

Esse resultado valida as regras e a regressão no Manager, não a cadeia operacional ponta a ponta. O agente dedicado ao Windows, `003`, consta como `Never connected`; os demais agentes Windows visíveis estão desconectados. O Guest Additions deixou de atualizar o estado da VM Windows, a tela do PowerShell não respondeu e WinRM 5985 não estava acessível. Nenhuma simulação nova foi enviada ao endpoint. A validação operacional continua em 3/5; `110130` e `110140` ainda precisam de evidência real do Windows. `110130` passou no fixture, mas segue bloqueada operacionalmente pela ausência observada de Sysmon Event ID 13.
