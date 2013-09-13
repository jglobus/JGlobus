#/usr/bin/env bash
GRIDSHIB_HOME=$(cd "`dirname $0`/.." && pwd)
java $JAVA_OPTS -Dgridshib.home=$GRIDSHIB_HOME -Dorg.globus.gridshib.config=$GRIDSHIB_HOME/gridshib-bootstrap.properties -cp "$GRIDSHIB_HOME/lib/*" org.teragrid.ncsa.gridshib.tool.gram.GRAMAuditQueryTool "$@"
