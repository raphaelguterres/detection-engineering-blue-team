# Simulação benigna: criação de conta local

## Objetivo

Validar `DET-WIN-LOCALACCOUNT-001` de forma não destrutiva por meio da fixture de regressão.

## Método seguro

O caso positivo em `tests/fixtures/net-user-add.json` representa o Event ID 1 esperado. Não crie contas em endpoints compartilhados ou de produção apenas para testar uma regra. Em um laboratório autorizado, siga o procedimento interno de gestão de identidades, use uma conta temporária sem privilégios e remova-a imediatamente após a validação.

## Resultado esperado

Um processo `net.exe` com `user <nome> /add` deve gerar o rule ID `100140`.

