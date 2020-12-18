The "meaningless CA" is an interoperable, untrusted CA with a well-known private key and DN:

Auto Issued X.509 Certificate Mechanism (AIXCM)
http://www.ietf.org/internet-drafts/draft-moreau-pkix-aixcm-00.txt

This archive contains an implementation of the meaningless CA:

http://gridshib.globus.org/downloads/meaningless-ca.tar.gz
http://gridshib.globus.org/downloads/meaningless-ca.zip

The archive includes the meaningless CA certificate and its private key, as well as an end-entity credential issued by the meaningless CA.  Also included is a signing policy file suitable for inclusion in a Globus trusted certificates directory.

The meaningless EEC has an X.509-bound SAML token, which contains the same attributes bound to a GridShib CA-issued EEC.  Thus the meaningless EEC and a GridShib CA-issued EEC are more-or-less interchangeable.

Certificates issued by the meaningless CA are useful for testing purposes.  They are preferable to self-signed certificates since the latter are known to be incompatible with existing implementations (such as Globus) and standards (such as RFC3820).

Contents

certificates/7a55e286.0
certificates/7a55e286.signing_policy
ca-cert.pem
ca-key.pem
ca-config.properties
eec.pem
eec-key.pem
eec-req.pem

Description

Files ca-cert.pem and ca-key.pem are the PEM-encoded certificate and private key of the "meaningless CA" as specified in AIXCM.  The content of file 7a55e286.0 in the certificates directory is identical to ca-cert.pem, that is, the PEM-encoded certificate of the meaningless CA.

The certificates directory is suitable for use as a Globus trusted certificates directory (by setting the X509_CERT_DIR environment variable, for instance).  Obviously, end-entity certificates (EECs) signed by the meaningless CA are inherently untrusted, so use these certificates with care.

Files eec.pem and eec-key.pem are the PEM-encoded certificate and private key of an EEC signed by the meaningless CA.  File eec-req.pem is the certificate signing request used by meaningless CA to sign the EEC.  The ca-config.properties file was used to create the X.509 SAML extension bound to the EEC.

The EEC in this archive is intended to be used for testing purposes only.

The GridShib Project
http://gridshib.globus.org/

