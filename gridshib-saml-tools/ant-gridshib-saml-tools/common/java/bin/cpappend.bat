rem ---------------------------------------------------------------------------
rem Append to CLASSPATH
rem
rem $Id$
rem ---------------------------------------------------------------------------

rem Process the first argument
if ""%1"" == """" goto end
set LOCALCLASSPATH=%LOCALCLASSPATH%;%1
shift

rem Process the remaining arguments
:setArgs
if ""%1"" == """" goto doneSetArgs
set LOCALCLASSPATH=%LOCALCLASSPATH% %1
shift
goto setArgs
:doneSetArgs
:end
