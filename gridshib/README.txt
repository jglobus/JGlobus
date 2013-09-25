The code currently depends on the following that are not in standard
Maven repositories:

a. Globus opensaml 1.1 that apparently is OpenSAML 1.1 with some of
   the fixes in OpenSAML 2.0 backported to 1.1.

b. commons-cli 2.0 that was never released.

c. An old version of Shibboleth utilities.

The first 2 of the above have been inserted into a gridshib-common/repo
and the last in gridshib-saml-tools/repo

There are junit test cases that run in the standard way:

mvn test

There are also tests for the command-line interface that can be run as:

mvn integration-test

Maven runs thru both of the above phases when invoked as:

mvn install

The installed artifacts are:

gridshib-common-<version>-javadoc.jar
gridshib-common-<version>-sources.jar
gridshib-common-<version>.jar

gridshib-saml-tools-<version>-javadoc.jar
gridshib-saml-tools-<version>-sources.jar
gridshib-saml-tools-<version>.jar
gridshib-saml-tools-<version>-config-cli-doc.tar.bz2
gridshib-saml-tools-<version>-config-cli-doc.tar.gz


The javadoc jars have the API documentation.

The tar ball gridshib-saml-tools-<version>-config-cli-doc.tar.gz has
the configuration files, command line tools and non-API documentation.
