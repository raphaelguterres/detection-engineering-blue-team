# Simulação benigna: criação de conta local

## Objetivo

Validar `DET-WIN-LOCALACCOUNT-001` com um processo `net.exe` benigno, sem deixar uma conta ativa ou persistente.

## Execução controlada

O executor cria uma conta única desabilitada usando a API LocalAccounts. A senha aleatória permanece em memória como `SecureString` e não entra na linha de comando nem no relatório. Em seguida, executa `net user <conta> * /add /active:no` para gerar o Event ID 1 do processo; como a conta já existe, o comando de `/add` é uma tentativa duplicada inofensiva. O fluxo apaga a conta no `finally` e confirma que ela não existe mais.

Essa validação cobre a telemetria da tentativa de criação (`net.exe`, `/add`), que é o sinal usado pela regra. A criação da conta desabilitada é feita separadamente para provar que o artefato temporário existe e pode ser removido com segurança.

## Limites de segurança

- Não execute em endpoints compartilhados ou de produção.
- Não adicione a conta a grupos locais ou remotos.
- Não faça logoff, não habilite acesso remoto e não use a conta para login.
- Se a remoção falhar, remova a conta antes de encerrar a sessão.

## Resultado esperado

O processo `net.exe` com `user <nome> * /add` deve gerar o Event ID 1 e o alerta `110140`; a conta deve permanecer desabilitada e ser removida no mesmo fluxo.

## Variante automatizada

O [executor remoto](../../docs/lab-automation.md) inclui essa variante automatizada e exige `--include-account`. O código de saída não zero do `net.exe` é esperado porque a conta já existe; o sucesso do teste depende do evento Sysmon, alerta correlacionado e limpeza confirmada.

