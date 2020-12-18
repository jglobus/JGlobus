The GridShib CA is an online, shib-enabled CA:

http://gridshib.globus.org/docs/gridshib-ca/

This archive contains the trusted certificate of an instance of the GridShib CA:

http://gridshib.globus.org/downloads/gridshib-ca-cert.tar
http://gridshib.globus.org/downloads/gridshib-ca-cert.zip

The archive includes the GridShib CA certificate and a signing policy file suitable for inclusion in a Globus trusted certificates directory.

An EEC issued by the GridShib CA has an X.509-bound SAML token, which contains the same attributes bound to the Meaningless EEC.  Thus a GridShib CA-issued EEC and the Meaningless EEC are more-or-less interchangeable.

Certificates issued by this instance of the GridShib CA are useful for testing purposes.  They are preferable to self-signed certificates since the latter are known to be incompatible with existing implementations (such as Globus) and standards (such as RFC3820).

Contents

certificates/bfcd1f28.0
certificates/bfcd1f28.signing_policy

Description

The certificates directory is suitable for use as a Globus trusted certificates directory (by setting the X509_CERT_DIR environment variable, for instance).

The GridShib Project
http://gridshib.globus.org/

