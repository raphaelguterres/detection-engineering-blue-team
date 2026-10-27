# Simulação benigna: alteração de Run Key

## Objetivo

Validar `DET-WIN-RUNKEY-001` com um valor temporário que não executa programa algum.

## Execução

Em um host autorizado com Sysmon Event ID 13, execute:

```powershell
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'DetectionEngineeringDemo' -Value 'cmd.exe /c echo DETECTION-TEST' -Force
```

## Resultado esperado

O evento de alteração de registro deve conter a chave `Run` e gerar o rule ID `100130`.

## Limpeza

```powershell
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'DetectionEngineeringDemo'
```

