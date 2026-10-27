# Simulação benigna: criação de tarefa agendada

## Objetivo

Validar `DET-WIN-SCHTASKS-001` com uma tarefa descartável que apenas escreve texto no console.

## Execução

Em um host autorizado, abra um terminal elevado e execute:

```powershell
schtasks.exe /create /tn DetectionEngineeringDemo /sc once /st 23:59 /tr "cmd.exe /c echo DETECTION-TEST" /f
```

## Resultado esperado

O Event ID 1 de `schtasks.exe` contém `/create` e deve gerar o rule ID `110120`.

## Limpeza

```powershell
schtasks.exe /delete /tn DetectionEngineeringDemo /f
```

