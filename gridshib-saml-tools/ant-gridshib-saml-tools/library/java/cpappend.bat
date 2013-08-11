rem ---------------------------------------------------------------------------
rem Append to CLASSPATH
rem
rem $Id: cpappend.bat,v 1.1.1.1 2007/03/05 23:29:46 tfreeman Exp $
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
