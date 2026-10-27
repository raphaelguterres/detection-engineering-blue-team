# Simulação benigna: PowerShell com `-EncodedCommand`

## Objetivo

Produzir telemetria de criação de processo para validar `DET-WIN-PS-ENC-001` sem baixar, executar ou persistir código externo.

## Pré-requisitos

- Host Windows isolado ou autorizado.
- Sysmon com Event ID 1 encaminhado ao Wazuh.
- Regra `110100` carregada no Wazuh manager.

## Execução

Abra um PowerShell comum e execute:

```powershell
$value = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "DETECTION-TEST"'))
powershell.exe -NoProfile -EncodedCommand $value
```

## Resultado esperado

- Sysmon registra Event ID 1 para `powershell.exe`.
- O comando contém `-EncodedCommand`.
- Wazuh gera alerta com rule ID `110100` e técnica `T1059.001`.

## Diagnóstico quando não houver alerta

1. No endpoint, confirme se o evento existe no canal `Microsoft-Windows-Sysmon/Operational` com Event ID 1 e se `Sysmon64` está ativo.
2. Confirme que o serviço do agente Wazuh está ativo e que o `ossec.conf` coleta esse canal.
3. No manager, valide a configuração e a carga da regra `110100`. O `wazuh-logtest` (CLI e API `/logtest`) não reproduz o decoder `windows_eventchannel`; um JSON sintético pode ser aceito como JSON genérico e não prova a detecção de um evento Sysmon. Valide com um evento coletado pelo agente Windows ou com uma fixture fiel ao formato EventChannel processada pelo `analysisd` ([limitação documentada no projeto Wazuh](https://github.com/wazuh/wazuh/issues/40614)).
4. Consulte os logs do agente e do manager antes de repetir a simulação. Registre o resultado como **não detectado** até a evidência do alerta aparecer no Wazuh. Para depuração, habilite `logall_json` somente durante uma janela curta e controlada, inspecione a evidência necessária e restaure o valor original logo após o teste.

## Limpeza e rollback

O comando apenas escreve texto no console e não deixa artefatos. Se a regra precisar ser removida, siga o campo `rollback` no catálogo.

