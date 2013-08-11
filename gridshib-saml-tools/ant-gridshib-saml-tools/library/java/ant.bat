@echo off
setlocal

REM Find the necessary resources
set ANT_HOME=.

REM We need a JVM
if not defined JAVA_HOME  (
  echo Error: JAVA_HOME is not defined.
  exit /b
)

if not defined JAVACMD (
  set JAVACMD="%JAVA_HOME%\bin\java.exe"
)

if not exist %JAVACMD% (
  echo Error: JAVA_HOME is not defined correctly.
  echo Cannot execute %JAVACMD%
  exit /b
)

if defined CLASSPATH (
  set LOCALCLASSPATH=%CLASSPATH%
)

REM add in the dependency .jar files
for %%i in (%ANT_HOME%\lib\*.jar) do (
	call %ANT_HOME%\cpappend.bat %%i
)
for %%i in (%ANT_HOME%\endorsed\*.jar) do (
	call %ANT_HOME%\cpappend.bat %%i
)

if exist %JAVA_HOME%\lib\tools.jar (
    set LOCALCLASSPATH=%LOCALCLASSPATH%;%JAVA_HOME%\lib\tools.jar
)

if exist %JAVA_HOME%\lib\classes.zip (
    set LOCALCLASSPATH=%LOCALCLASSPATH%;%JAVA_HOME%\lib\classes.zip
)

%JAVACMD% -cp "%LOCALCLASSPATH%" -Dant.home="%ANT_HOME%" %ANT_OPTS% org.apache.tools.ant.Main -e %*
