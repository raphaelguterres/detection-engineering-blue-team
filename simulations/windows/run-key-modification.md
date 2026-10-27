# Simulação benigna: alteração de Run Key

## Objetivo

Validar `DET-WIN-RUNKEY-001` com um valor temporário que não executa programa algum.

## Execução

Em uma VM Windows isolada e autorizada com Sysmon Event ID 13, execute:

```powershell
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'DetectionEngineeringDemo' -Value 'cmd.exe /c echo DETECTION-TEST' -Force
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'DetectionEngineeringDemo'
```

## Resultado esperado

O primeiro comando cria o valor temporário e o segundo o remove imediatamente. O Sysmon registra o Event ID 13, que deve conter a chave `Run` e gerar o rule ID `110130`.

## Limpeza

Não faça logoff ou reinicie a VM entre os comandos. Se a remoção falhar, execute-a novamente antes de encerrar a sessão.

