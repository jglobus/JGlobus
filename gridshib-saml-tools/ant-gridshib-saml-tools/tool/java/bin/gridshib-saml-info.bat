@echo off
setlocal

REM the GridShib installation directory
if not defined GRIDSHIB_HOME (
  echo Error: GRIDSHIB_HOME is not defined.
  exit /b 1
)

call %GRIDSHIB_HOME%\bin\java org.globus.gridshib.tool.saml.SAMLSecurityInfoTool %*

