# Simulação benigna: PowerShell com `-EncodedCommand`

## Objetivo

Produzir telemetria de criação de processo para validar `DET-WIN-PS-ENC-001` sem baixar, executar ou persistir código externo.

## Pré-requisitos

- Host Windows isolado ou autorizado.
- Sysmon com Event ID 1 encaminhado ao Wazuh.
- Regra `100100` carregada no Wazuh manager.

## Execução

Abra um PowerShell comum e execute:

```powershell
$value = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "DETECTION-TEST"'))
powershell.exe -NoProfile -EncodedCommand $value
```

## Resultado esperado

- Sysmon registra Event ID 1 para `powershell.exe`.
- O comando contém `-EncodedCommand`.
- Wazuh gera alerta com rule ID `100100` e técnica `T1059.001`.

## Limpeza e rollback

O comando apenas escreve texto no console e não deixa artefatos. Se a regra precisar ser removida, siga o campo `rollback` no catálogo.

