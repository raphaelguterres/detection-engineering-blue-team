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
| Conta local | Cria uma conta local única já desabilitada com senha aleatória em memória e executa `net user <nome> * /add /active:no` como tentativa duplicada inofensiva | Remove e confirma ausência em `finally`; não adiciona grupos |

A automação usa nomes únicos em vez do nome fixo das simulações manuais. A tarefa automática é `ONSTART` para evitar diferenças de formato de data; não reinicie a VM durante o teste. O HKCU é o da **conta WinRM**, que pode ser diferente da sessão gráfica. Para a conta local, a API LocalAccounts cria uma conta temporária desabilitada; o `net user /add` seguinte tenta criá-la novamente, gerando telemetria sem habilitar ou alterar a conta. A saída não zero desse comando é esperada; o artefato desabilitado é conferido antes da ação e removido no mesmo fluxo. A senha não é argumento de processo nem campo de relatório.

`finally` permite limpeza quando o script continua executando, mas não garante recuperação após desligamento da VM ou interrupção abrupta do processo. Estado desconhecido é registrado como falha e exige recuperação antes de repetir.

## Evidência e interpretação

Cada cenário recebe um identificador aleatório. A confirmação exige simultaneamente: execução concluída, limpeza confirmada, evento Sysmon local e alerta da regra correta para o agente configurado com o marcador daquele teste e o nível definido no XML versionado. Para PowerShell, o marcador é o próprio conteúdo codificado na linha de comando.

O coletor lê até os últimos 8 MiB do `alerts.json` atual e devolve contagens e níveis, sem logs brutos. Não consulta arquivos rotacionados nem garante captura sob volume extremo; `scan_truncated` indica leitura parcial. Um alerta ausente dentro da janela significa `alert_missing`, não uma prova definitiva de ausência na plataforma inteira. `telemetry_missing` indica que o evento local não foi observado. O tempo de espera de alertas é configurável entre 5 e 300 segundos, além dos limites de conexão de cada chamada.

Os arquivos `.lab/runs/<id>/report.json` e `report.md` guardam o resultado. `.lab/journal/<id>/report.json` registra a intenção antes de cada simulação para recuperação de execução interrompida. Nenhum desses diretórios entra no Git; revise manualmente qualquer evidência que venha a publicar.

## Instalação e rollback

`deploy` roda o quality gate local, detecta duplicidades e preserva o nome do arquivo remoto que já contém cada regra. Recusa arquivos compartilhados com outras regras. Salva os conteúdos anteriores e hashes em `/var/ossec/backup/detection-engineering/<id>/manifest.json`, com acesso restrito. A validação `wazuh-analysisd -t` precede o reinício; falha durante a instalação tenta restaurar as alterações desta execução.

O `pipeline` executa os fixtures positivos e negativos após instalar. Para `110130` e `110140`, o replay usa `wazuh-logtest-legacy -c` com uma cópia temporária das regras nativas e locais: somente nessa cópia, a base Windows `60000` é adaptada para o decoder JSON. Isso exercita a árvore Windows, inclusive a regra nativa `92300`, sem editar a configuração ativa nem reiniciar o Manager. A cópia é removida ao sair, inclusive em falha. O binário legacy é necessário porque o cliente `wazuh-logtest` desta versão não aceita configuração isolada; se estiver ausente, a etapa falha. Os demais fixtures continuam no replay JSON direto e não comprovam o caminho EventChannel. Falha nessa regressão solicita rollback do backup criado. Já a falta de telemetria no endpoint interrompe a aprovação operacional, sem atribuir automaticamente a falha ao XML instalado.

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

### Bloqueio de autenticação Windows — 29/10/2026

Na retomada seguinte, a console da VM mostrou o Windows inicializando e depois a tela de login do usuário `Administrator`. A sessão requer autenticação. Não foram inseridas credenciais nem executados comandos no Windows. Os canais WinRM (5985/5986), RDP (3389), SSH (22) e SMB (445) não responderam nos endereços conhecidos `192.168.56.101` e `192.168.0.10`. O agente Wazuh `003` continua `Never connected`.

As validações operacionais restantes ficam bloqueadas até o Windows estar autenticado e acessível por um canal remoto autorizado, com agente conectado. Depois disso, confirmar Sysmon Event ID 13 e executar as simulações `110130` e `110140` com evidência e limpeza verificadas. Não reiniciar nem alterar credenciais como parte desta retomada.

### Retomada após reiniciar a VM — 30/10/2026

Após o operador reiniciar a VM, o Guest Additions atualizou novamente e o desktop Windows carregou. O agente `004` (`WIN-TP3GFAE2OCB`, Windows Server 2022) ficou `Active`; o agente cadastrado `003` continua `Never connected`. `Test-WSMan` respondeu em `192.168.56.101:5985`, mas uma sessão `Invoke-Command` usando a identidade atual falhou com `ExplicitCredentialsRequired`. Não existe `.lab/windows.credential.xml` neste controlador. Nenhum segredo foi lido, solicitado ou inserido.

O inventário local ignorado pelo Git foi atualizado para apontar a coleta de evidência ao agente `004` e o endpoint WinRM observado. As portas 5986, RDP, SSH e SMB não responderam; apenas o listener WinRM HTTP está aberto. O handshake `Test-WSMan` comprova o listener, não autenticação nem autorização para comandos.

As regras `110130` e `110140` ainda não foram simuladas: falta uma credencial WinRM autorizada e armazenada localmente em formato DPAPI para o usuário que executa o executor. Depois de disponibilizar esse arquivo, executar primeiro `preflight`, confirmar Sysmon/Wazuh e a telemetria Event ID 13; então rodar `run --scenario runkey` e `run --scenario localaccount`, confirmando alerta e limpeza em cada relatório antes de contar a validação como operacional.

### Credencial DPAPI criada — 30/10/2026

O arquivo `.lab/windows.credential.xml` agora existe no controlador e `Import-Clixml` o reconhece como `PSCredential` para `Administrator`. A tentativa de sessão remota continua falhando com `0x8009030e` (`ExplicitCredentialsRequired`/sessão de logon inexistente), que também informa que a identidade do servidor não foi validada. O `TrustedHosts` do controlador não contém o endpoint. A tentativa de adicioná-lo foi negada por falta de privilégio administrativo; nenhuma alteração foi feita no registro nem no Windows convidado.

O próximo passo é adicionar somente `192.168.56.101` à lista `TrustedHosts` no controlador usando PowerShell elevado, ou configurar WinRM HTTPS com certificado verificável. Não usar curinga. Depois, confirmar a sessão autenticada antes de executar o preflight. A credencial exportada é local à conta e máquina controladoras; não copiá-la para a VM convidada nem para o Git.

### Continuação da validação — 29/10/2026

O acesso WinRM autenticado foi estabelecido e o executor identificou o endpoint `WIN-TP3GFAE2OCB`, com `WazuhSvc` e `Sysmon64` em execução. O preflight passou em uma execução anterior. A configuração Sysmon original não coletava `RegistryEvent`; foi preservado backup em `C:\Sysmon\sysmon-lab.xml.pre-DE-9ae43321ccfd4e8b.bak` e aplicada a configuração versionada em `simulations/windows/sysmon-runkey-lab-config.xml`, preservando os filtros preexistentes e incluindo alterações na Run Key.

A simulação Run Key subsequente gerou um evento Sysmon local (Event ID 13) e confirmou a limpeza do valor. O Manager não encontrou alerta naquela execução. A simulação de conta local também confirmou limpeza e ausência da conta ao final, mas a criação falhou e não conta como detecção operacional; dois eventos locais de criação de processo foram observados. O replay do formato do evento no `wazuh-logtest` casou com a regra `110140`, que confirma a condição da regra, não o alerta em produção.

Na retomada atual, `preflight` foi bloqueado antes de qualquer simulação: SSH ao Kali e WinRM ao Windows retornaram erro de transporte/autenticação. A repetição Run Key foi abortada antes de modificar o endpoint. Relatórios sanitizados: `.lab/runs/DE-c8b1bf099c33466c/report.json` (preflight) e `.lab/runs/DE-89414b492f064249/report.json` (run sem cenários). A contagem operacional permanece **3/5**. Para retomar, restabeleça os dois canais e rode `python scripts/lab/run.py preflight`; após sucesso, investigue o caminho evento Sysmon → agente → Manager antes de repetir as simulações.

### Tentativa seguinte — 30/10/2026

Com as VMs informadas como ligadas, o preflight `.lab/runs/DE-7fbdf0c482b74782/report.json` voltou a falhar antes de iniciar cenários. A checagem do host não alcançou Kali SSH em `192.168.56.102:22` nem Windows WinRM em `192.168.56.101:5985`. Nenhuma simulação foi executada. A diferença entre o estado “executando” no VirtualBox e a indisponibilidade de rede indica que falta reconectar/verificar o adaptador host-only ou atualizar os endereços observados das VMs; não alterar inventário até identificar os IPs corretos. A contagem continua **3/5**.

### Diagnóstico VirtualBox — 30/10/2026

A consulta somente leitura ao VirtualBox confirmou o adaptador `VirtualBox Host-Only Ethernet Adapter` ativo (`192.168.56.1/24`, estado `Up`), DHCP do host-only habilitado e ambas as VMs em estado `running`, com cabo conectado na interface host-only. O Guest Additions reporta Kali `192.168.56.102` e Windows Server `192.168.56.101`; ambos coincidem com `.lab/config.json`, portanto não foi necessário trocar IPs nem editar o inventário. Entretanto, ping e conexões TCP para SSH `:22` e WinRM `:5985` falharam, e as entradas ARP dos MACs das VMs permaneceram `Stale`. Não houve alteração de adaptadores ou simulação. O bloqueio está na resposta/rede efetiva dos convidados ou nos serviços; retomar após inspecionar no console das VMs o estado da interface host-only, endereço ativo, rota e serviços SSH/WinRM.

### Validação via Guest Additions — 30/10/2026

O Guest Control confirmou que Kali `eth2` está `UP` com `192.168.56.102/24`, SSH ativo na porta 22 e Docker ativo. No Windows, a terceira interface está `UP` com `192.168.56.101/24`; `WinRM`, `WazuhSvc` e `Sysmon64` estão em execução, WinRM escuta em `0.0.0.0:5985`, e a regra de firewall HTTP-In está habilitada para a sub-rede local. O Kali alcança o host (`192.168.56.1`) e o listener WinRM do Windows; há também conexão Windows→Manager na porta 1514 e o agente `004` está ativo. Assim, a rede host-only e os serviços das VMs estão operacionais; as sondagens TCP iniciadas pelo processo controlador desta sessão não alcançam os convidados, então a verificação/execução foi feita via Guest Additions sem mudar a rede.

Para a regra `110130`, uma janela curta de diagnóstico habilitou `logall_json=yes`, gerou a Run Key, confirmou Event ID 13 local e limpeza e observou o evento nos archives. O valor foi restaurado para `logall_json=no` e verificado após reiniciar o Manager. O `full_log` arquivado, submetido diretamente ao `wazuh-logtest`, casou com a regra local. A descoberta foi que o `TargetObject` recebido contém barras invertidas duplicadas; a expressão da regra foi alterada para aceitar uma ou mais. O deploy versionado do conjunto completo criou backup `DE-c608acfdb80e4aa8`; os 11 casos de regressão passaram, incluindo o novo caso positivo com separadores duplicados.

Apesar do replay positivo, as execuções reais posteriores não produziram alerta `110130` em `alerts.json`. Alertas `92200` observados durante as consultas correspondiam ao arquivo do worker que foi temporariamente copiado para `C:\Windows\Temp`, não à alteração da Run Key; não contabilizar como detecção. A simulação Run Key permanece fora da contagem operacional. Investigar a diferença entre o replay do `full_log` e o processamento ao vivo do `analysisd` antes de alterar novamente a regra.


### Conclusão de Run Key e conta local — 30/10/2026

As duas validações restantes foram concluídas via Guest Control. `110130` gerou um alerta de nível 12 após Event ID 13; `110140` gerou dois alertas de nível 12 após a tentativa benigna com conta previamente criada e desabilitada. Marcador e agente foram correlacionados no Manager. A Run Key e a conta foram removidas, e uma consulta independente confirmou a ausência de ambas. O total histórico passa a **5/5**; as três primeiras regras não foram reexecutadas nesta etapa.

A causa de `110130` envolvia a árvore de regras: o replay JSON direto contornava o caminho `windows_eventchannel`, e a regra nativa `92300` encerrava a análise do evento real em nível zero. A regra local agora é filha de `61615` e `92300`. A `110140` foi ligada ao grupo `sysmon_event1`. O deploy preservou backup no Manager; seu identificador está em `.lab/current-backup.json`, fora do Git.

O replay de `110130` e `110140` agora usa uma cópia isolada da árvore Windows, adaptando apenas a base dessa cópia para JSON. Os 11 casos passaram no Wazuh. Os 19 testes offline, incluindo preservação da configuração ativa em falha do replay, passaram fora do sandbox; dentro dele, a restrição de arquivos impedia o teste de restauração. Quality gate e sintaxe PowerShell também passaram. O Manager permaneceu ativo com `logall_json=no`.

A diferença entre replay JSON e EventChannel também é descrita no [repositório oficial do Wazuh](https://github.com/wazuh/wazuh/discussions/25405). Aqui, a precedência de `92300` foi reproduzida em cópia isolada e a correção foi confirmada com eventos reais. A confirmação cobre `alerts.json`; a indexação e a visualização no dashboard não foram verificadas nesta etapa.
