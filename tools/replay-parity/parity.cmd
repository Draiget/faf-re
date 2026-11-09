@echo off
rem Replay parity runner; see README.md. Needs Python 3.14+ (stdlib zstd); FAF_PY overrides it.
set "PY=%FAF_PY%"
if "%PY%"=="" set "PY=C:\Program Files\Microsoft SDKs\Azure\CLI2\python.exe"
"%PY%" -X utf8 "%~dp0parity.py" %*
