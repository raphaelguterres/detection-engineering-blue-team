# Simulação benigna: telemetria de Rundll32 em caminho gravável

## Objetivo

Validar `DET-WIN-RUNDLL32-001` por meio de fixture controlada, sem criar ou executar DLLs.

## Método seguro

Este cenário é validado no pipeline pelos eventos sintéticos em `tests/fixtures/rundll32-user-writable-path.json`. Para um teste operacional, use somente uma DLL de teste assinada e aprovada pela sua organização, em host isolado, seguindo o processo interno de change control.

## Resultado esperado

Um Event ID 1 cujo processo seja `rundll32.exe` e contenha caminho sob `Users`, `ProgramData`, `Temp` ou `AppData` deve gerar o rule ID `110110`.

## Limpeza e rollback

Remova os artefatos de teste autorizados conforme o procedimento local. Para reverter a detecção, siga o campo `rollback` no catálogo.

