@echo off
echo [*] Starting M3 Test Runner in isolated network (se6013-m1-lab_lab)...
echo [*] Mounting current directory: %cd%

docker run --rm --network se6013-m1-lab_lab -v "%cd%:/app" -w /app python:3.10-slim python runner.py

echo.
echo [+] Execution finished. Check local 'evidence/' directory for results.
pause