# Simulação benigna: criação de conta local

## Objetivo

Validar `DET-WIN-LOCALACCOUNT-001` de forma não destrutiva por meio da fixture de regressão.

## Execução controlada

Em uma VM Windows isolada e autorizada, abra um PowerShell elevado e execute:

```powershell
net user DetectionEngineeringTemp * /add
net user DetectionEngineeringTemp /delete
```

O primeiro comando solicita a senha localmente, sem registrá-la no histórico nem na linha de comando. Use uma senha exclusiva para o laboratório. A conta não deve receber grupos, privilégios ou acesso remoto. O segundo comando a remove imediatamente.

## Limites de segurança

- Não execute em endpoints compartilhados ou de produção.
- Não adicione a conta a grupos locais ou remotos.
- Não faça logoff, não habilite acesso remoto e não use a conta para login.
- Se a remoção falhar, remova a conta antes de encerrar a sessão.

## Resultado esperado

Um processo `net.exe` com `user <nome> * /add` deve gerar o rule ID `110140`.

