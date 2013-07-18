/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef GLOBUS_DONT_DOCUMENT_INTERNAL
/**
 * @file grid_proxy_info.h
 * Globus GSI Proxy Utils
 * @author Sam Lang, Sam Meder
 *
 * $RCSfile: grid_saml_info.c,v $
 * $Revision: 1.1.1.1 $
 * $Date: 2007/03/05 23:24:10 $
 */
#endif

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


int                                     debug = 0;

#define SHORT_USAGE_FORMAT \
"\nSyntax: %s [-help][-f proxyfile][-subject][...][-e [-h H][-b B]]\n"

static char *  LONG_USAGE = \
"\n" \
"    Options\n" \
"    -help, -usage             Displays usage\n" \
"    -version                  Displays version\n" \
"    -debug                    Displays debugging output\n" \
"    -file <proxyfile>  (-f)   Non-standard location of proxy\n" \
"\n";


#   define args_show_version() \
    { \
        char buf[64]; \
        sprintf( buf, \
                 "%s-%s", \
                 PACKAGE, \
                 VERSION); \
        fprintf(stderr, "%s\n", buf); \
        globus_module_deactivate_all(); \
        exit(0); \
    }

#   define args_show_short_help() \
    { \
        fprintf(stderr, \
                SHORT_USAGE_FORMAT \
                "\nUse -help to display full usage.\n", \
                program); \
        globus_module_deactivate_all(); \
    }

#   define args_show_full_usage() \
    { \
        fprintf(stderr, SHORT_USAGE_FORMAT \
                "%s", \
                program, \
                LONG_USAGE); \
        globus_module_deactivate_all(); \
        exit(0); \
    }

#   define args_error_message(errmsg) \
    { \
        fprintf(stderr, "\nERROR: %s\n", errmsg); \
        args_show_short_help(); \
        globus_module_deactivate_all(); \
        exit(1); \
    }

#   define args_error(argp, errmsg) \
    { \
        char buf[1024]; \
        sprintf(buf, "option %s : %s", argp, errmsg); \
        args_error_message(buf); \
    }

void
globus_i_gsi_proxy_utils_print_error(
    globus_result_t                     result,
    int                                 debug,
    const char *                        filename,
    int                                 line);

#define GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR \
    globus_i_gsi_proxy_utils_print_error(result, debug, __FILE__, __LINE__)

#define STATUS_OK               0
#define STATUS_EXPIRED          1
#define STATUS_NOT_FOUND        2
#define STATUS_CANT_LOAD        3
#define STATUS_NO_NAME          4
#define STATUS_BAD_OPTS         5
#define STATUS_INTERNAL         6

int 
main(
    int                                 argc, 
    char *                              argv[])
{
    char *                              program;
    char *                              argp;
    int                                 arg_index;
    char *                              proxy_filename = NULL;
    globus_gsi_cred_handle_t            proxy_cred = NULL;
    STACK_OF(X509)*                     cert_stack = NULL;
    int                                 index;
    globus_result_t                     result;
    FILE                                *out_stream = stdout;
    FILE                                *debug_stream = stdout;
    

    if(globus_module_activate(GLOBUS_OPENSSL_MODULE) !=
       (int)GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\n\nERROR: Couldn't load module: GLOBUS_OPENSSL_MODULE.\n"
            "Make sure Globus is installed correctly.\n\n");
        exit(1);
    }

    
    if(globus_module_activate(GLOBUS_GSI_PROXY_MODULE) != (int)GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\n\nERROR: Couldn't load module: GLOBUS_GSI_PROXY_MODULE.\n"
            "Make sure Globus is installed correctly.\n\n");
        exit(1);
    }

    /* XXX Do this right */
    globus_l_gsi_saml_activate();

    if (strrchr(argv[0], '/'))
    {
        program = strrchr(argv[0], '/') + 1;
    }
    else
    {
        program = argv[0];
    }

    /* Parsing phase 1: check all arguments that they are valid */
    for (arg_index = 1; arg_index < argc; arg_index++)
    {
        argp = argv[arg_index];

        if (strncmp(argp, "--", 2) == 0)
        {
            if (argp[2] != '\0')
            {
                args_error(argp, "double-dashed options "
                           "are not allowed");
            }
            else
            {
                arg_index = argc + 1;                   /* no more parsing */
                continue;
            }
        }
        if ((strcmp(argp, "-help") == 0) ||
            (strcmp(argp, "-usage") == 0))
        {
            args_show_full_usage();
        }
        else if (strcmp(argp, "-version") == 0)
        {
            args_show_version();
        }
        else if ((strcmp(argp, "-file") == 0) ||
                 (strcmp(argp, "-f") == 0)   )
        {
            if ((arg_index + 1 >= argc) || (argv[arg_index + 1][0] == '-'))
            {
                args_error(argp, "needs a file name argument");
            }
            else
            {
                proxy_filename = argv[++arg_index];
            }
        }
        else if ((strcmp(argp, "-debug") == 0))
        {
            debug = 1;
        }
        else
            args_error(argp, "unrecognized option");
    }

    if(proxy_filename)
    {
        result = GLOBUS_GSI_SYSCONFIG_CHECK_KEYFILE(proxy_filename);
    }
    else
    { 
        result = GLOBUS_GSI_SYSCONFIG_GET_PROXY_FILENAME(
            &proxy_filename,
            GLOBUS_PROXY_FILE_INPUT);
    }
    
    if(result != GLOBUS_SUCCESS)
    {
       globus_libc_fprintf(
           stderr,
           "\nERROR: Couldn't find a valid proxy.\n");
       GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }

    result = globus_gsi_cred_handle_init(&proxy_cred, NULL);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't initialize proxy credential handle\n");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }
    
    result = globus_gsi_cred_read_proxy(proxy_cred, proxy_filename);
    if(result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't read proxy from: %s\n", proxy_filename);
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
    }

    if (debug)
    {
        globus_libc_fprintf(
            debug_stream,
            "Parsing SAML Asssertions:\n");
    }

    result = globus_gsi_saml_get_cert_stack(proxy_cred,
                                            &cert_stack);
    if (result != GLOBUS_SUCCESS)
    {
        globus_libc_fprintf(
            stderr,
            "\nERROR: Couldn't get certificate stack\b");
        GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
        goto done;
    }

    if (debug)
    {
        globus_libc_fprintf(
            debug_stream,
            "Certificate stack has %d certs\n",
            sk_X509_num(cert_stack));
    }
    
    for (index = 0; index < sk_X509_num(cert_stack); index++)
    {
        X509_EXTENSION *ext;
        X509 *cert;
        int assertion_trusted = GLOBUS_FALSE;
        globus_gsi_cert_utils_cert_type_t cert_type;

   
        cert = sk_X509_value(cert_stack, index);

        if (debug)
        {
            char *subject = NULL;
        
            subject = X509_NAME_oneline(
                X509_get_subject_name(cert),
                NULL, 0);
            
            globus_libc_fprintf(
                debug_stream,
                "Parsing certificate #%d: %s\n",
                index + 1,
                subject);

            OPENSSL_free(subject);
        }   

        result = 
            globus_gsi_saml_get_assertion(cert, &ext);

        if (result != GLOBUS_SUCCESS)
        {
            globus_libc_fprintf(
                stderr,
                "\nERROR: Couldn't get asertion from certificate\b");
                continue;
        }
            
        if (ext != NULL)
        {
            if (debug)
            {
                globus_libc_fprintf(
                    debug_stream,
                    "Found an assertion.\n");
            }

            /*
             * Is this assertion trusted? In order for it to be trusted, it
             * must be in the EEC or be signed and bound to a DN of the proxy
             * cert or it's issuer.
             */
            result =
                globus_gsi_cert_utils_get_cert_type(cert,
                                                    &cert_type);
            
            if (result != GLOBUS_SUCCESS)
            {
                globus_libc_fprintf(
                    stderr,
                    "\nERROR: Couldn't get certificate type\b");
                GLOBUS_I_GSI_PROXY_UTILS_PRINT_ERROR;
                continue;
            }

            if (cert_type == GLOBUS_GSI_CERT_UTILS_TYPE_EEC) 
            {
                assertion_trusted = GLOBUS_TRUE;

                if (debug)
                {
                    globus_libc_fprintf(
                        debug_stream,
                        "Assertion trusted because it is in EEC\n");
                }
                
            }

            /* XXX Check signature on certificate */
            /* XXX Check for DN match */

            globus_libc_fprintf(
                out_stream,
                "%s Assertion\n",
                (assertion_trusted ? "Trusted" : "UNTRUSTED"));
            
            /* XXX Is there a nicer way to get at value here? */
            ASN1_STRING_print_ex_fp(
                out_stream,
                ext->value,
                0);
            /*
              ASN1_STIRNG_print(BIO *bp, ext->value);
            */
            globus_libc_fprintf(
                debug_stream,
                "\n");
        }
    }

  done:
    if (cert_stack)
    {
        sk_X509_free(cert_stack);
        cert_stack = NULL;
    }

    if (debug)
    {
        globus_libc_fprintf(
            debug_stream,
            "Done parsing SAML Asssertions\n");
    }

    globus_module_deactivate(GLOBUS_OPENSSL_MODULE);
    globus_module_deactivate(GLOBUS_GSI_PROXY_MODULE);

    return (0);
}

void
globus_i_gsi_proxy_utils_print_error(
    globus_result_t                     result,
    int                                 debug,
    const char *                        filename,
    int                                 line)
{
    globus_object_t *                   error_obj;
    char *                              error_string = NULL;

    error_obj = globus_error_get(result);
    error_string = globus_error_print_chain(error_obj);

    if(debug)
    {
        globus_libc_fprintf(stderr, "       %s:%d: %s", filename, line, error_string);
    }
    else 
    {
        globus_libc_fprintf(stderr, "       %s\nUse -debug for further information.\n", error_string);
    }
    if(error_string)
    {
       globus_libc_free(error_string);
    }
    globus_object_free(error_obj);
    globus_module_deactivate_all();
    exit(1);
}
