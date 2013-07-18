@echo off
setlocal

REM the GridShib installation directory
if not defined GRIDSHIB_HOME (
  echo Error: GRIDSHIB_HOME is not defined.
  exit /b 1
)

REM the GridShib base directory
if not defined GRIDSHIB_SAML_BASEDIR (
  set GRIDSHIB_SAML_BASEDIR=%GRIDSHIB_HOME%\etc
)

type %GRIDSHIB_SAML_BASEDIR%\meaningless-ca\eec.pem > "%TEMP%\x509up_u_%USERNAME%"
type %GRIDSHIB_SAML_BASEDIR%\meaningless-ca\eec-key.pem >> "%TEMP%\x509up_u_%USERNAME%"
echo Meaningless EEC installed at %TEMP%\x509up_u_%USERNAME%

exit /b 0

