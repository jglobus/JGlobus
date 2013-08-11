
#define SAMLAUTHNEXT_OID       "1.3.6.1.4.1.3536.1.1.1.10"
#define SAMLAUTHNEXT_SN        "SAMLAUTHNEXT"
#define SAMLAUTHNEXT_LN        "SAML Authentication Assertion Extension"

/* Place holder for our final decided on OID */
#define SAMLASSERTION_OID       SAMLAUTHNEXT_OID
#define SAMLASSERTION_SN        SAMLAUTHNEXT_SN
#define SAMLASSERTION_LN        "SAML Assertion Extension"

void
globus_l_gsi_saml_activate();

globus_result_t
globus_gsi_saml_get_assertion(
    X509* cert,
    X509_EXTENSION **ext
);

globus_result_t
globus_gsi_saml_get_cert_stack(
    globus_gsi_cred_handle_t     proxy_cred,
    STACK_OF(X509)**             pcert_stack
);
