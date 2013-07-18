

#include "globus_common.h"
#include "globus_error.h"
#include "globus_gsi_cert_utils.h"
#include "globus_gsi_system_config.h"
#include "globus_gsi_proxy.h"
#include "globus_gsi_credential.h"
#include "globus_openssl.h"
#ifdef WIN32
#include "globus_gssapi_config.h"
#endif

#include "saml_util.h"

/* XXX TODO:
 *    Real error handling
 *    Real module activiation
 */

/* XXX Figure out how to do this right */
void
globus_l_gsi_saml_activate()
{
    /*
     * Register OIDs
     */
    OBJ_create(SAMLAUTHNEXT_OID,
               SAMLAUTHNEXT_SN,
               SAMLAUTHNEXT_LN);
}


globus_result_t
globus_gsi_saml_get_assertion(
    X509* cert,
    X509_EXTENSION **pext)
{
    int                         nid;
    int                         ext_loc;
    X509_EXTENSION*             extension = NULL;
    /* List of short names for extensions to look for */
    char*                       extSNs[] = 
        {
            SAMLAUTHNEXT_SN,
            NULL
        };
    char**                      sn;
    globus_result_t             result = GLOBUS_FAILURE;
    
    /*
     * Go through list of possible OIDs. Take the first extension we
     * find, assuming we will only have one per cert.
     */
    for (sn = extSNs; *sn != NULL; sn++)
    {
        nid = OBJ_sn2nid(*sn);
        if (nid == NID_undef)       
        {   
            globus_libc_fprintf(
                stderr,
                "\nERROR: Couldn't get numeric ID for %s extension",
                *sn);
        }   
    
        ext_loc = X509_get_ext_by_NID(
            cert,
            nid,
            -1);
    
        if (ext_loc == -1)
        {
            continue;
        }
        
        extension = X509_get_ext(cert,
                                 ext_loc);
        
        if (extension == NULL)
        {
            globus_libc_fprintf(
                stderr,
                "Can't find extension in X509 cert at "
                "expected location: %d in extension stack", ext_loc);
            continue;
        }

        /* Success */
        break;
    }
    
    *pext = extension;
    
    return GLOBUS_SUCCESS;
}

/*
 * Return a stack of X509 certificates starting with the proxy cert
 * and going back up the chain to the last certificate that inherits
 * from its issuer (either the EEC or a proxy that does not have a
 * policy of inhertitAll).
 *
 * XXX There really is nothing SAML-specific about this function.
 *
 * cert_stack needs to be freed using sk_X509_free
 */
globus_result_t
globus_gsi_saml_get_cert_stack(
    globus_gsi_cred_handle_t     proxy_cred,
    STACK_OF(X509)**             pcert_stack
)
{
    STACK_OF(X509)*              cert_chain = NULL;
    STACK_OF(X509)*              cert_stack = NULL;
    X509*                        proxy_cert = NULL;
    X509*                        last_cert = NULL;
    globus_result_t              result = GLOBUS_FAILURE;
    
    result = globus_gsi_cred_get_cert_chain(proxy_cred,
                                            &cert_chain);
    if (result != GLOBUS_SUCCESS)
    {
        goto done;
    }

    result = globus_gsi_cred_get_cert(proxy_cred,
                                      &proxy_cert);
    if (result != GLOBUS_SUCCESS)   
    {       
        goto done;
    }

    cert_stack = sk_X509_new_null();
    
    /* Start with proxy cert */
    sk_X509_push(cert_stack, proxy_cert);
    last_cert = proxy_cert;
    proxy_cert = NULL; /* To avoid free() now that it is on stack */
    
    while (sk_X509_num(cert_chain) > 0)
    {
        X509_NAME *issuer_name;
        X509 *cert;
        int index;
        int issuer_index;
        globus_gsi_cert_utils_cert_type_t cert_type;
        int inherit = GLOBUS_FALSE;
        
        
        /*
         * Does this cert inherit rights from issuer?
         */
        result =
            globus_gsi_cert_utils_get_cert_type(last_cert,
                                                &cert_type);
        
        if (result != GLOBUS_SUCCESS)
        {
            goto done;
        }
        
        switch (cert_type)
        {
          case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_IMPERSONATION_PROXY:
          case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_IMPERSONATION_PROXY:
          case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_PROXY:
            /*
             * Full-fledged impersonation proxies, definitely inherit.
             */
            inherit = GLOBUS_TRUE;
            break;

          case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_3_LIMITED_PROXY:
          case GLOBUS_GSI_CERT_UTILS_TYPE_GSI_2_LIMITED_PROXY:
          case GLOBUS_GSI_CERT_UTILS_TYPE_RFC_LIMITED_PROXY:
            /*
             * Limited proxy, inherit all rights but job creation.
             */
            inherit = GLOBUS_TRUE;
            break;

          default:
            /*
             * EEC, restricted proxy or CA. No inheritance.
             */
            inherit = GLOBUS_FALSE;
            break;
        }

        if (!inherit)
        {
            /*
             * This certificate does not inherit from issuer.
             * We are done building the stack.
             */
            break;
        }
        
        /*
         * This certificate inherits from its issuer.
         * Find issuer and put on stack. We're assuming path validation
         * has been completed, so we can trust issuer and subject
         * names to determine issuer.
         */
        issuer_name = X509_get_issuer_name(last_cert);
        issuer_index = -1;
        for (index = 0; index < sk_X509_num(cert_chain); index++)
        {
            X509_NAME *subject;
            
            cert = sk_X509_value(cert_chain, index);
            if (X509_NAME_cmp(issuer_name, X509_get_subject_name(cert)) == 0)
            {       
                issuer_index = index;
                break;
            }
        }
        
        if (issuer_index == -1)
        {
            /*
             * Issuer not found. Probably shouldn't happen with well-
             * formed credentials since any type of certificate which
             * inherits should have an issuer in the chain.
             * In any case, we're done.
             */
            break;
        }
        
        /*
         * Add issuer to stack, remove it from chain and repeat process.
         */
        sk_X509_push(cert_stack, cert);
        sk_X509_delete(cert_chain, issuer_index);
        last_cert = cert;
    }
    
    result = GLOBUS_SUCCESS;
    *pcert_stack = cert_stack;
    
  done:
    if (cert_chain)
    {
        sk_X509_free(cert_chain);
    }
    if (proxy_cert)
    {
        X509_free(proxy_cert);
    }
    return result;
}

