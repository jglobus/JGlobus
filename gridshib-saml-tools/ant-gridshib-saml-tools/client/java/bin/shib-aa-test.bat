@echo off
setlocal

REM the IdP installation directory
if not defined GRIDSHIB_HOME (
  echo Error: GRIDSHIB_HOME is not defined.
  exit /b
)

call %GRIDSHIB_HOME%\bin\java org.globus.gridshib.client.saml.query.ShibTestClient %*

exit /b
