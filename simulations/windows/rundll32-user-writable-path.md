# Simulação benigna: Rundll32 com caminho inexistente em diretório gravável

## Objetivo

Validar `DET-WIN-RUNDLL32-001` sem criar, carregar ou executar DLLs.

## Execução

Em uma VM Windows isolada e autorizada, abra um PowerShell comum e execute:

```powershell
rundll32.exe "C:\Users\Public\DetectionEngineering\missing.dll,EntryPoint"
```

O arquivo referenciado não deve existir. O Windows pode exibir uma mensagem de erro porque a biblioteca não existe; esse é o resultado esperado. O objetivo é somente produzir a telemetria de criação de processo para `rundll32.exe` com um caminho sob um diretório gravável pelo usuário.

## Limites de segurança

- Não crie `missing.dll` ou qualquer outra DLL para este teste.
- Não execute DLLs, scripts, downloads ou payloads.
- Interrompa o teste se o caminho apontar para um arquivo existente.

## Resultado esperado

O Sysmon deve registrar Event ID 1 no canal `Microsoft-Windows-Sysmon/Operational`. O processo `rundll32.exe` e o caminho sob `Users` devem gerar o rule ID `110110` com a técnica `T1218.011`.

## Limpeza e rollback

Nenhum artefato é criado. Feche a mensagem de erro, se houver. Para reverter a detecção, siga o campo `rollback` no catálogo.

