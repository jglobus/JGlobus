@echo off
setlocal

REM depends on cpappend.bat

REM the JDK installation directory
if not defined JAVA_HOME  (
  echo Error: JAVA_HOME is not defined.
  exit /b 1
)

if not defined JAVACMD (
  set JAVACMD="%JAVA_HOME%\bin\java.exe"
)

if not exist %JAVACMD% (
  echo Error: JAVA_HOME is not defined correctly.
  echo Cannot execute %JAVACMD%
  exit /b 1
)

REM the GridShib installation directory
if not defined GRIDSHIB_HOME (
  echo Error: GRIDSHIB_HOME is not defined.
  exit /b 1
)

set LOCAL_OPTS=-Dgridshib.home="%GRIDSHIB_HOME%"
set LOCAL_OPTS=-Djava.endorsed.dirs="%GRIDSHIB_HOME%\endorsed" %LOCAL_OPTS%

REM the log4j config file (Bug: must be URL) (try: relative URL etc/log4j.properties)
set LOCAL_OPTS=-Dlog4j.configuration="%GRIDSHIB_HOME%\etc\log4j.properties" %LOCAL_OPTS%

REM path to bootstrap properties file
if defined GRIDSHIB_CONFIG (
  set LOCAL_OPTS=-Dorg.globus.gridshib.config="%GRIDSHIB_CONFIG%" %LOCAL_OPTS%
)

REM initialize the local classpath
if defined CLASSPATH (
  set LOCALCLASSPATH=%CLASSPATH%
)

REM add jar files to the local classpath
for %%i in (%GRIDSHIB_HOME%\lib\*.jar) do (
  call %GRIDSHIB_HOME%\bin\cpappend.bat %%i
)

REM add servlet jar to the local classpath, if possible
if not defined CATALINA_HOME (
  REM echo Warning: CATALINA_HOME is not defined.
) ELSE (
  set LOCALCLASSPATH=%LOCALCLASSPATH%;%CATALINA_HOME%\common\lib\servlet-api.jar
)

REM run java
%JAVACMD% %LOCAL_OPTS% -cp "%LOCALCLASSPATH%" %*
