# Simulação benigna: criação de tarefa agendada

## Objetivo

Validar `DET-WIN-SCHTASKS-001` com uma tarefa descartável que apenas escreve texto no console.

## Execução

Em uma VM Windows isolada e autorizada, abra um PowerShell elevado e execute:

```powershell
schtasks.exe /create /tn DetectionEngineeringDemo /sc once /st 23:59 /tr "cmd.exe /c echo DETECTION-TEST" /f
schtasks.exe /delete /tn DetectionEngineeringDemo /f
```

## Resultado esperado

O primeiro comando cria uma tarefa descartável e o segundo a remove imediatamente. O Event ID 1 de `schtasks.exe` contém `/create` e deve gerar o rule ID `110120`.

## Limpeza

Se o segundo comando falhar, execute-o novamente antes de encerrar a sessão. Não aguarde o horário agendado e não execute a tarefa.

