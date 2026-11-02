@echo off
setlocal EnableExtensions DisableDelayedExpansion
title FASE 3 - Conferir exportacao independente do Discover
cd /d "%~dp0.."
echo.
echo ============================================================
echo  FASE 3 - CORRELACAO INDEPENDENTE DO DASHBOARD DISCOVER
echo ============================================================
echo  Este verificador NAO conecta nas VMs nem modifica o Wazuh.
echo  Salve o CSV exportado pela interface Discover em:
echo  .lab\phase3-discover.csv
echo  Ele exige 6 eventos com id, rule.id, agent.id, timestamp.
echo.
where python >nul 2>&1
if errorlevel 1 (
  echo ERRO: Python nao encontrado no PATH.
  pause
  exit /b 2
)
if not exist ".lab\phase3-manager.jsonl" (
  echo ERRO: Exportacao privada do Manager ausente.
  pause
  exit /b 2
)
if not exist ".lab\phase3-indexer.jsonl" (
  echo ERRO: Exportacao privada do Indexer ausente.
  pause
  exit /b 2
)
if not exist ".lab\phase3-discover.csv" (
  echo ERRO: Exportacao independente da interface Discover ausente.
  echo Nao reutilize o JSON do Dev Tools nem copie o Indexer como Discover.
  pause
  exit /b 2
)
python scripts\phase3_compare_discover_export.py
set "RC=%errorlevel%"
echo.
if "%RC%"=="0" (
  echo.
  echo CORRELACAO 6/6 CANDIDATA A ACEITE.
  echo Confirme que o CSV veio de Download as CSV na interface Discover.
  echo Somente depois registre o aceite final na Issue 4 e roadmap.
) else (
  echo.
  echo FASE 3 NAO ACEITA. Nao marque milestone como finalizado.
)
echo Nenhuma credencial, simulacao ou alteracao de servico realizada.
pause
exit /b %RC%
