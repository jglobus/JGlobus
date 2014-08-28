/*
 * Copyright 1999-2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS,WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */
package org.globus.gsi.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.globus.common.CoGProperties;

import org.globus.gsi.util.CertificateLoadUtil;

import org.globus.gsi.CertificateRevocationLists;

import org.globus.gsi.trustmanager.CRLChecker;
import org.globus.gsi.trustmanager.CertificateChecker;
import org.globus.gsi.trustmanager.DateValidityChecker;
import org.globus.gsi.trustmanager.IdentityChecker;
import org.globus.gsi.trustmanager.SigningPolicyChecker;
import org.globus.gsi.trustmanager.UnsupportedCriticalExtensionChecker;
import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;

import org.globus.gsi.X509ProxyCertPathParameters;
import org.globus.gsi.X509ProxyCertPathValidatorResult;

import org.globus.gsi.provider.SigningPolicyStore;
import org.globus.gsi.provider.SigningPolicyStoreException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.gsi.proxy.ProxyPolicyHandler;

import org.globus.gsi.SigningPolicy;
import org.globus.gsi.SigningPolicyParser;
import org.junit.Before;
import org.junit.Test;

public class TestProxyPathValidator {

    public static final String BASE = "validatorTest/";

    public static String[] crlNames = {
            "ca2crl.r0", "testca3.r0"
    };

    public static String[] certs = {
            // 0, GSIConstants.CertificateType.CA), TestCA.pem
            "TestCA1.pem",
            // 1, GSIConstants.CertificateType.EEC,
            "eecFromTestCA1.pem",
            // 2, GSIConstants.CertificateType.GSI_2_PROXY), gsi2fullproxy.pem
            "gsi2fullproxy.pem",
            // 3, GSIConstants.CertificateType.GSI_2_LIMITED_PROXY), gsi2limitedproxy.pem
            "gsi2limitedproxy.pem",
            // 4, double GSIConstants.CertificateType.GSI_2_LIMITED_PROXY), gsi2limited2xproxy.pem (issued by 3)
            "gsi2limited2xproxy.pem",
            // 5, GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY),  gsi3impersonationproxy.pem
            "gsi3impersonationproxy.pem",
            // 6, GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY), gsi3independentproxy.pem
            "gsi3independentproxy.pem",
            // 7, GSIConstants.CertificateType.GSI_3_LIMITED_PROXY), gsi3limitedproxy.pem
            "gsi3limitedproxy.pem",
            // 8, GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY),   gsi3restrictedproxy.pem
            "gsi3restrictedproxy.pem",
            // double
            // 9, GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY), gsi3impersonation2xproxy.pem
            "gsi3impersonation2xproxy.pem",
            // 10, GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY),  gsi3independent2xproxy.pem
            "gsi3independent2xproxy.pem",
            // pathLen = 0
            // 11, GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY), gsi3impersonationp0proxy.pem
            "gsi3impersonationp0proxy.pem",
            // pathLen = 1
            // 12, GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY), gsi2independentp1proxy.pem
            "gsi3independentp1proxy.pem",
            // pathLen = 2
            // 13, GSIConstants.CertificateType.CA),
            "testca.pem",
            // 14, GSIConstants.CertificateType.EEC)
            "testeec1.pem",
            // 15, GSIConstants.CertificateType.EEC)
            "testeec2.pem",
            // pathLen = 1
            // 16, GSIConstants.CertificateType.CA)
            "testca2.pem",      // crl for this, 16
            // 17, GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY),
            "testgsi3proxy.pem",
            // for CRL test
            // 18, GSIConstants.CertificateType.CA),
            "testca3.pem",
            // 19, GSIConstants.CertificateType.EEC),
            "crl_usercert.pem",
            // 20, GSIConstants.CertificateType.GSI_2_PROXY),
            "crl_proxy.pem",
            // 21 (all good)
            // GSIConstants.CertificateType.CA)
            "ca1cert.pem",
            // 22, GSIConstants.CertificateType.EEC
            "user1ca1.pem",
            // 23, GSIConstants.CertificateType.EEC)
            "user2ca1.pem",
            // 24, GSIConstants.CertificateType.EEC)
            "user3ca1.pem",
            // 25
            // GSIConstants.CertificateType.CA)
            "ca2cert.pem",   // crl 25
            // must be revoked (in ca2crl.r0)
            // 26, GSIConstants.CertificateType.EEC)
            "user1ca2.pem",
            // must be revoked (in ca2crl.r0)
            // 27, GSIConstants.CertificateType.EEC),
            "user2ca2.pem",
            // 28, GSIConstants.CertificateType.EEC)
            "user3ca2.pem",
            // 29
            // gsi3 limited impersonation signs a gsi3 independent
            "gsi3independentFromLimitedProxy.pem",
            // 30
            // gsi3 limited impersonation signs a gsi3 impersonation
            "gsi3limitedimpersonation2xproxy.pem",
            // 31
            // gsi3 independent signs a gsi3 impersonation
            "gsi3impersonationFromIndependentProxy.pem",
            // 32
            // gsi3 pathlength 0 impersonatipon proxy signs proxy
            "gsi3FromPathZeroProxy.pem",
            // 33
            // gsi3 path length 1 independent proxy signs proxy
            "gsi3FromPathOneProxy.pem",
            // 34
            // gsi3FrompathOneProxy signs proxy
            "gsi3FromPathOneIssuedProxy.pem",
            // 35
            // gsi2 proxy generated from gsi3impersonationProxy
            "gsi2proxyFromgsi3.pem",
            // 36
            // gsi3 proxy generated from gsi2fullproxy
            "gsi3proxyFromgsi2.pem"
    };

    public static String[] badCerts = {
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIICFTCCAX6gAwIBAgIDClb3MA0GCSqGSIb3DQEBBAUAMGIxCzAJBgNVBAYTAlVT\n" +
                    "MQ8wDQYDVQQKEwZHbG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFi\n" +
                    "b3JhdG9yeTEMMAoGA1UECxMDTUNTMQ4wDAYDVQQDEwVnYXdvcjAeFw0wMjEyMTgw\n" +
                    "NzEzNDhaFw0wMjEyMTgxOTE4NDhaMIGCMQswCQYDVQQGEwJVUzEPMA0GA1UEChMG\n" +
                    "R2xvYnVzMSQwIgYDVQQKExtBcmdvbm5lIE5hdGlvbmFsIExhYm9yYXRvcnkxDDAK\n" +
                    "BgNVBAsTA01DUzEOMAwGA1UEAxMFZ2F3b3IxDjAMBgNVBAMTBXByb3h5MQ4wDAYD\n" +
                    "VQQDEwVwcm94eTBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQCplfu3OZH5AfYgoYKi\n" +
                    "KFmGZnbj3+ZwJm45B6Ef7qwW7Le7FP4eirljObqijgn8ao0gGqy38LYbaTntToqX\n" +
                    "iy5fAgERMA0GCSqGSIb3DQEBBAUAA4GBAKnNy0VPDzzD6++7i9a/yegPX2+OVI6C\n" +
                    "7oss1/4sSw2gfn/q8qNiGdt1kr4W3JJACdjgnik8fokNS7pDMdXKi3Wx6E0HhgKz\n" +
                    "eRIm5r6Vj7nshVBAv60Xmfju3yaOZsDnj8p0t8Fjc8ekeZowLEdRn7PCEQPylMOp\n" +
                    "2puR03MaPiFj\n" +
                    "-----END CERTIFICATE-----"
            ,
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIICBDCCAW2gAwIBAgIDAx4rMA0GCSqGSIb3DQEBBAUAMGIxCzAJBgNVBAYTAlVT\n" +
                    "MQ8wDQYDVQQKEwZHbG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFi\n" +
                    "b3JhdG9yeTEMMAoGA1UECxMDTUNTMQ4wDAYDVQQDEwVnYXZvcjAeFw0wMjEyMTgw\n" +
                    "NzIxMThaFw0wMjEyMTgxOTI2MThaMHIxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKEwZH\n" +
                    "bG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFib3JhdG9yeTEMMAoG\n" +
                    "A1UECxMDTUNTMQ4wDAYDVQQDEwVnYXdvcjEOMAwGA1UEAxMFcHJveHkwWjANBgkq\n" +
                    "hkiG9w0BAQEFAANJADBGAkEAx2fp80b+Yo0zCwjYJdIjzn0N3ezzcD2h2bAr/Nop\n" +
                    "w/H6JB4heiVGMeydMlSJHyI7J/s5l8k39G/KVrBGT9tRJwIBETANBgkqhkiG9w0B\n" +
                    "AQQFAAOBgQCRRvTdW6Ddn1curWm515l/GoAoJ76XBFJWfusIZ9TdwE8hlkRpK9Bd\n" +
                    "Rrao4Z2YO+e3UItn45Hs+8gzx+jBB1AduTUor603Z8AXaNbF/c+gz62lBWlcmZ2Y\n" +
                    "LzuUWgwZLd9HdA2YBgCcT3B9VFmBxcnPjGOwWT29ZUtyy2GXFtzcDw==\n" +
                    "-----END CERTIFICATE-----"
    };

    public static String[] testCerts = {
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIB7zCCAVigAwIBAgICAbowDQYJKoZIhvcNAQEEBQAwVzEbMBkGA1UEChMSZG9l\n" +
                    "c2NpZW5jZWdyaWQub3JnMQ8wDQYDVQQLEwZQZW9wbGUxJzAlBgNVBAMTHlZpamF5\n" +
                    "YSBMYWtzaG1pIE5hdGFyYWphbiAxNzkwODAeFw0wMzAxMTcyMjExMjJaFw0wMzAx\n" +
                    "MTgxMDE2MjJaMGcxGzAZBgNVBAoTEmRvZXNjaWVuY2VncmlkLm9yZzEPMA0GA1UE\n" +
                    "CxMGUGVvcGxlMScwJQYDVQQDEx5WaWpheWEgTGFrc2htaSBOYXRhcmFqYW4gMTc5\n" +
                    "MDgxDjAMBgNVBAMTBXByb3h5MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANGP+xct\n" +
                    "lDYMPm11QKnACvqs95fbPRehvUi6/dizZ+VrDOU1OTUoXA0t6HRgtmJ8XthEUKxU\n" +
                    "MVsxjXtoZOzfuFECAwEAATANBgkqhkiG9w0BAQQFAAOBgQBqFTcN/qqvTnyI4z26\n" +
                    "lv1lMTuRIjL9l6Ug/Kwxuzjpl088INky1myFPjKsWMYzh9nXIQg9gg2dJTno5JHB\n" +
                    "++u0Fw2iNrTjswu4hvqYZn+LoSGchH2XyCUssuOWCbW4IkN8/Xzfre2oC2EieECC\n" +
                    "w+jjGhcqPrxvkHh8xXYroqA0Sg==\n" +
                    "-----END CERTIFICATE-----"
            ,
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIDLDCCAhSgAwIBAgICAbowDQYJKoZIhvcNAQEFBQAwdTETMBEGCgmSJomT8ixk\n" +
                    "ARkWA25ldDESMBAGCgmSJomT8ixkARkWAmVzMSAwHgYDVQQLExdDZXJ0aWZpY2F0\n" +
                    "ZSBBdXRob3JpdGllczEZMBcGA1UECxMQRE9FIFNjaWVuY2UgR3JpZDENMAsGA1UE\n" +
                    "AxMEcGtpMTAeFw0wMjA5MjMyMzQ2NDRaFw0wMzA5MjMyMzQ2NDRaMFcxGzAZBgNV\n" +
                    "BAoTEmRvZXNjaWVuY2VncmlkLm9yZzEPMA0GA1UECxMGUGVvcGxlMScwJQYDVQQD\n" +
                    "Ex5WaWpheWEgTGFrc2htaSBOYXRhcmFqYW4gMTc5MDgwgZ8wDQYJKoZIhvcNAQEB\n" +
                    "BQADgY0AMIGJAoGBAORYHsPQU3yVlTsC/29CDoEYF82PVlolQk5s+1m6A7m3VvML\n" +
                    "TKh4ja6cKtq7C5rBUIWdyklkU3eXSSmiAzjJrVOmfWK3RR465A5tfvJLmXKWaq3U\n" +
                    "7SvI6v3vx4Jzy4MJs46TDAr4v9JRJG2yshoxruRy2gDsn4F5NfLLevDNwzSLAgMB\n" +
                    "AAGjaDBmMBEGCWCGSAGG+EIBAQQEAwIF4DAOBgNVHQ8BAf8EBAMCBPAwHwYDVR0j\n" +
                    "BBgwFoAUVBeIygPBOSa4VabEmfQrAqu+AOkwIAYDVR0RBBkwF4EVdmlqYXlhbG5A\n" +
                    "bWF0aC5sYmwuZ292MA0GCSqGSIb3DQEBBQUAA4IBAQC/dxf5ZuSrNrxslHUZfDle\n" +
                    "V8SPnX5roBUOuO2EPpEGYHB25Ca+TEi0ra0RSRuZfGmY13/aS6CzjBF+6GED9MLo\n" +
                    "6UdP1dg994wpGZ2Mj0dZoGE7we10NrSvFAS3u7uXrTTegeJoDpo1k9YVsOkK9Lu9\n" +
                    "Sg+EztnMGa1BANWf779Qws5J9xUR2Nip0tBkV3IRORcBx0CoZzQnDIWyppmnkza2\n" +
                    "mhgEv6CXYYB4ucCFst0P2Q3omcWrtHexoueMGOV6PtLFBst5ReOaZWU+q2D30t3b\n" +
                    "GFITa0aayXTlb6gWgo3z/O/K5GZS5jF+BA3j1e8IhxqeibT1rVHF4W4ZMjGhBcwa\n" +
                    "-----END CERTIFICATE-----"
            ,
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIEqjCCBBOgAwIBAgIBLzANBgkqhkiG9w0BAQUFADBbMRkwFwYDVQQKExBET0Ug\n" +
                    "U2NpZW5jZSBHcmlkMSAwHgYDVQQLExdDZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEc\n" +
                    "MBoGA1UEAxMTQ2VydGlmaWNhdGUgTWFuYWdlcjAeFw0wMTEyMjEyMzQ4MzdaFw0w\n" +
                    "NDAxMTAyMzQ4MzdaMHUxEzARBgoJkiaJk/IsZAEZFgNuZXQxEjAQBgoJkiaJk/Is\n" +
                    "ZAEZFgJlczEgMB4GA1UECxMXQ2VydGlmaWNhdGUgQXV0aG9yaXRpZXMxGTAXBgNV\n" +
                    "BAsTEERPRSBTY2llbmNlIEdyaWQxDTALBgNVBAMTBHBraTEwggEiMA0GCSqGSIb3\n" +
                    "DQEBAQUAA4IBDwAwggEKAoIBAQDhgzoAt5viFffXWG6P0KSf/dO0mrEbgpuKIHDa\n" +
                    "RdHkxJGaoBgRO2D+YV4Wh+JcKlz64v2ScYHCgGbKoaE+cGM/O06xkLCV0pyT4Xvj\n" +
                    "6/R80jqwzzRw8aYz9iE/wjljK1ehb+oJ6TJlnotCVBd7TlHODYfXXblt67/Uk1uu\n" +
                    "4l17jCdfk4mUn/2Bdeae4EMibj7Vc1dkPkyY47ZADTeFXMNDyp4yGFeIDZQ6h+YH\n" +
                    "27+t1/TDuEH1R4PpklRpSbppGprI8hv2P6uEKTySjAEkww9xVzenN6oULeafFJuS\n" +
                    "t6Ui6BFxc1OuxMq/s0PDiFh8bPMhzJWBfzaNPHnYrFDWcDwHAgMBAAGjggHeMIIB\n" +
                    "2jAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFFQXiMoDwTkmuFWmxJn0KwKrvgDp\n" +
                    "MB8GA1UdIwQYMBaAFJvOT/K8vVhwMdXyMg5+nr3iURTnMA8GA1UdEwEB/wQFMAMB\n" +
                    "Af8wgY8GA1UdHwSBhzCBhDCBgaAaoBiGFmh0dHA6Ly9lbnZpc2FnZS5lcy5uZXSB\n" +
                    "AgDsol+kXTBbMRkwFwYDVQQKExBET0UgU2NpZW5jZSBHcmlkMSAwHgYDVQQLExdD\n" +
                    "ZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEcMBoGA1UEAxMTQ2VydGlmaWNhdGUgTWFu\n" +
                    "YWdlcjCB5AYDVR0gBIHcMIHZMIHWBgoqhkiG90wDBgQBMIHHMF8GCCsGAQUFBwIC\n" +
                    "MFMwJhYfRVNuZXQgKEVuZXJneSBTY2llbmNlcyBOZXR3b3JrKTADAgEBGilFU25l\n" +
                    "dC1ET0UgU2NpZW5jZSBHcmlkIENlcnRpZmljYXRlIFBvbGljeTBkBggrBgEFBQcC\n" +
                    "ARZYaHR0cDovL2VudmlzYWdlLmVzLm5ldC9FbnZpc2FnZSUyMERvY3MvRE9FU0cl\n" +
                    "MjBDQSUyMENlcnRpZmljYXRlJTIwUG9saWN5JTIwYW5kJTIwQ1BTLnBkZjANBgkq\n" +
                    "hkiG9w0BAQUFAAOBgQCaAdUregqwmCJG6j/h6uK2bTpcfa/SfpaYwsTy+zlf5r4P\n" +
                    "iY/wIRN0ZjJ4RrJQ/WUH16onNwb87JnYe0V4JYhATAOnp/5y9kl+iC4XvHBioVxm\n" +
                    "3sEADL40WAVREWBGZnyFqysXAEGfk+Wg7um5FzCwi6380GASKY0VujQG03f6Pg==\n" +
                    "-----END CERTIFICATE-----"
    };


    // Globus CA signing policy. Using globusca.pem and usercert.pem
    public static String signingPolicy =
            "access_id_CA      X509         '/C=TestCA1/CN=CA'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/*\"'";

    // Globus CA signing policy that causes usercert.pem to violate
    // the policy
    public static String signingPolicyViolation =
            "access_id_CA      X509         '/C=TestCA1/CN=CA'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/12*\"'";

    // Globus CA signing policy without relevant signing policy
    public static String signingPolicySansPolicy =
            "# Globus CA rights\naccess_id_CA      nonX509         '/C=US/O=Globus/CN=Globus Certification Authority'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/C=usa/O=Globus/*\"  \"/C=USA/O=Globus/*\"'\n# End of ca-signing-policy.conf";

    public X509Certificate[] goodCertsArr;
    public X509CRL[] crls;
    CertificateFactory factory;

    String crlDir;

    @Before
    public void setup() throws Exception {

        CoGProperties.getDefault().setProperty(CoGProperties.CRL_CACHE_LIFETIME, "1");
        CoGProperties.getDefault().setProperty(CoGProperties.CERT_CACHE_LIFETIME, "1");

        Security.addProvider(new MockGlobusProvider());

        factory = CertificateFactory.getInstance("X.509");

        ClassLoader loader = TestProxyPathValidator.class.getClassLoader();

        goodCertsArr = new X509Certificate[certs.length];
        for (int i = 0; i < certs.length; i++) {
            String name = BASE + certs[i];
            InputStream in = loader.getResourceAsStream(name);
            if (in == null) {
                throw new Exception("Unable to load: " + name);
            }
            goodCertsArr[i] = CertificateLoadUtil.loadCertificate(in);
        }


        crls = new X509CRL[crlNames.length];
        for (int i = 0; i < crlNames.length; i++) {
            String name = BASE + crlNames[i];
            InputStream in = loader.getResourceAsStream(name);
            if (in == null) {
                throw new Exception("Unable to load: " + name);
            }
            crls[i] = CertificateLoadUtil.loadCrl(in);
        }

        crlDir = loader.getResource(BASE).getPath();
    }

    private void validateChain(X509Certificate[] chainCerts, KeyStore keyStore, CertStore certStore,
                               SigningPolicyStore policyStore, X509Certificate expectedIdentity,
                               boolean expectedLimited) throws Exception {

        List<X509Certificate> certList = Arrays.asList(chainCerts);
        validateChain(certList, keyStore, certStore, policyStore, expectedIdentity, expectedLimited);
    }

    private void validateChain(List<? extends Certificate> certList,
                               KeyStore keyStore,
                               CertStore certStore,
                               SigningPolicyStore policyStore,
                               X509Certificate expectedIdentity,
                               boolean expectedLimited)
            throws Exception {

        CertPath certPath = factory.generateCertPath(certList);

        validateChain(certPath, keyStore, certStore, policyStore,
                expectedIdentity,
                expectedLimited);
    }

    private void validateChain(CertPath chain,
                               KeyStore keyStore,
                               CertStore certStore,
                               SigningPolicyStore policyStore,
                               X509Certificate expectedIdentity,
                               boolean expectedLimited)
            throws Exception {

        MockProxyCertPathValidator validator =
                new MockProxyCertPathValidator(false, false, false, false);
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                        false);
        X509ProxyCertPathValidatorResult result =
                (X509ProxyCertPathValidatorResult) validator
                        .engineValidate(chain, parameters
                        );

        assert (expectedLimited == result.isLimited());
        assert (expectedIdentity.equals(result.getIdentityCertificate()));
    }

    private void validateChainBuiltin(X509Certificate[] chainCerts,
                               KeyStore keyStore,
                               CertStore certStore,
                               SigningPolicyStore policyStore)
            throws Exception {

        List<X509Certificate> certList = Arrays.asList(chainCerts);
        CertPath certPath = factory.generateCertPath(certList);
        MockProxyCertPathValidator validator =
                new MockProxyCertPathValidator(false, false, false, true);
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                        false);
        X509ProxyCertPathValidatorResult result =
                (X509ProxyCertPathValidatorResult) validator
                        .engineValidate(certPath, parameters
                        );

    }

    private void validateError(X509Certificate[] certChain, KeyStore keyStore,
                               CertStore certStore,
                               SigningPolicyStore policyStore, String error)
            throws Exception {

        List<X509Certificate> certList = Arrays.asList(certChain);

        CertPath chain = factory.generateCertPath(certList);
        MockProxyCertPathValidator validator =
                new MockProxyCertPathValidator(false, false, false, false);
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                        false);
        boolean exception = false;
        try {
            X509ProxyCertPathValidatorResult result =
                    (X509ProxyCertPathValidatorResult) validator
                            .engineValidate(chain, parameters
                            );
        } catch (IllegalArgumentException e) {
            if (e.getMessage().indexOf(error) != -1) {
                exception = true;
            }
        } catch (CertPathValidatorException e) {
            if (e.getMessage().indexOf(error) != -1) {

                exception = true;
            }
        }

        assert (exception);
    }

    private void validateErrorBuiltin(X509Certificate[] certChain, KeyStore keyStore,
                                     CertStore certStore,
                                     SigningPolicyStore policyStore, String error)
            throws Exception {

        List<X509Certificate> certList = Arrays.asList(certChain);

        CertPath chain = factory.generateCertPath(certList);
        MockProxyCertPathValidator validator =
                new MockProxyCertPathValidator(false, false, false, true);
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                        false);
        boolean exception = false;
        try {
            X509ProxyCertPathValidatorResult result =
                    (X509ProxyCertPathValidatorResult) validator
                            .engineValidate(chain, parameters
                            );
        } catch (IllegalArgumentException e) {
            if (e.getMessage().indexOf(error) != -1) {
                exception = true;
            }
        } catch (CertPathValidatorException e) {
            if (e.getMessage().indexOf(error) != -1) {

                exception = true;
            }
        }

        assert (exception);
    }

    private void validateChainWithPolicy(X509Certificate[] chainCerts,
                                         KeyStore keyStore,
                                         CertStore certStore,
                                         SigningPolicyStore policyStore,
                                         boolean error)
            throws Exception {

        List<X509Certificate> certList = Arrays.asList(chainCerts);

        CertPath certPath = factory.generateCertPath(certList);

        MockProxyCertPathValidator validator =
                new MockProxyCertPathValidator(false, false, true, false);
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                        false);
        boolean exception = false;
        try {
            X509ProxyCertPathValidatorResult result =
                    (X509ProxyCertPathValidatorResult) validator.engineValidate(certPath, parameters);
        } catch (CertPathValidatorException exp) {
            exception = true;
        }

        assert (error == exception);
    }

    protected KeyStore getKeyStore(X509Certificate[] certificates)
            throws Exception {

        KeyStore keyStore = KeyStore.getInstance("MockKeyStore");
        keyStore.load(null, null);
        if (certificates != null) {
            for (X509Certificate certificate : certificates) {
                keyStore.setCertificateEntry(certificate.getSubjectDN().getName(), certificate);
            }
        }
        return keyStore;
    }

    @Test
    public void validateGsi2PathGood() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});

        TestCertParameters parameters = new TestCertParameters(null, this.crls);
        CertStore certStore = CertStore.getInstance("MockCertStore", parameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);

        // EEC, CA
        List<Certificate> tmpCerts = new Vector<Certificate>();
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        CertPath certPath = factory.generateCertPath(tmpCerts);

        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[1], false);

        // proxy, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[2]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);

        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[1], false);


        // limited proxy, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[3]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);

        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[1], true);

        // double limited proxy, limited proxy, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[4]);
        tmpCerts.add(goodCertsArr[3]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);

        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[1], true);
    }

    @Test
    public void validateRejectLimitedCheck() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});

        TestCertParameters certStoreParameters = new TestCertParameters(null, this.crls);

        CertStore certStore = CertStore.getInstance("MockCertStore", certStoreParameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);

        // limited proxy, EEC, CA
        List<Certificate> tmpCerts = new Vector<Certificate>();
        tmpCerts.add(goodCertsArr[3]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        CertPath certPath = factory.generateCertPath(tmpCerts);
        validateChain(certPath, keyStore, certStore, policyStore,
                goodCertsArr[1], true);

        MockProxyCertPathValidator validator =
                new MockProxyCertPathValidator(false, false, false, false);
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore,
                        true);
        boolean expected = false;
        try {
            X509ProxyCertPathValidatorResult result =
                    (X509ProxyCertPathValidatorResult) validator.engineValidate(certPath, parameters);

        } catch (CertPathValidatorException exp) {
            if ((exp.getMessage().indexOf("Limited") != -1)) {
                expected = true;
            }
        }
        assert (expected);

        parameters = new X509ProxyCertPathParameters(keyStore, certStore, policyStore, false);
        X509ProxyCertPathValidatorResult result =
                (X509ProxyCertPathValidatorResult) validator.engineValidate(certPath, parameters);
        assertTrue(result.isLimited());
        validator.clear();

        // a proxy chain with no limited proxy
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[2]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);
        parameters = new X509ProxyCertPathParameters(keyStore, certStore, policyStore, true);
        result = (X509ProxyCertPathValidatorResult) validator.engineValidate(certPath, parameters);
        assertFalse(result.isLimited());
    }

    @Test
    public void validateGsi3PathGood() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});

        TestCertParameters certStoreParameters = new TestCertParameters(null, this.crls);

        CertStore certStore = CertStore.getInstance("MockCertStore", certStoreParameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);

        // GSI 3 PC impersonation, EEC, CA
        List<Certificate> tmpCerts = new Vector<Certificate>();
        tmpCerts.add(goodCertsArr[5]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        CertPath certPath = factory.generateCertPath(tmpCerts);
        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[1], false);

        // GSI 3 PC independent, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[6]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);
        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[6], false);

        // GSI 3 PC imperson limited, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[7]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);
        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[1], true);

        // GSI 3 PC impersonation, GSI 3 PC limited impersonation, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[30]);
        tmpCerts.add(goodCertsArr[7]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);
        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[1], true);

        // GSI 3 PC impersonation, GSI 3 PC impersonation, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[9]);
        tmpCerts.add(goodCertsArr[5]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);
        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[1], false);

        // GSI 3 PC indepedent, GSI 3 PC independent, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[10]);
        tmpCerts.add(goodCertsArr[6]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        certPath = factory.generateCertPath(tmpCerts);
        validateChain(certPath, keyStore, certStore, policyStore, goodCertsArr[10], false);

        // GSI 3 PC impersonation, GSI 3 PC independent, EEC, CA
        tmpCerts.clear();
        tmpCerts.add(goodCertsArr[31]);
        tmpCerts.add(goodCertsArr[6]);
        tmpCerts.add(goodCertsArr[1]);
        tmpCerts.add(goodCertsArr[0]);
        validateChain(tmpCerts, keyStore, certStore, policyStore, goodCertsArr[6], false);

        // GSI 3 PC indepedent, GSI 3 PC limited impersonation, EEC, CA
        X509Certificate[] chain =
                new X509Certificate[]{goodCertsArr[29], goodCertsArr[7], goodCertsArr[1], goodCertsArr[0]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[29], false);

    }

    @Test
    public void validatePathWithRestrictedProxy() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});

        TestCertParameters certStoreParameters = new TestCertParameters(null, this.crls);

        CertStore certStore = CertStore.getInstance("MockCertStore", certStoreParameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);

        X509Certificate[] chain;

        // GSI 3 PC restricted, EEC, CA
        chain = new X509Certificate[]{goodCertsArr[8], goodCertsArr[1], goodCertsArr[0]};

        validateError(chain, keyStore, certStore, policyStore, "Unknown policy");

        // test proxy handler
        String policyId = "1.3.6.1.4.1.3536.1.1.1.8";
        Map<String, ProxyPolicyHandler> map = new HashMap<String, ProxyPolicyHandler>();
        map.put(policyId, new ProxyPolicyHandler() {
            public void validate(ProxyCertInfo info, CertPath path, int index) throws CertPathValidatorException {
                ProxyPolicy policy = info.getProxyPolicy();
                String pol = policy.getPolicyAsString();
                assertEquals("<AllPermissions...>\n\n", pol);
            }
        });
        chain = new X509Certificate[]{goodCertsArr[8], goodCertsArr[1], goodCertsArr[0]};

        List<Certificate> certList = new Vector<Certificate>();
        certList.add(chain[0]);
        certList.add(chain[1]);
        certList.add(chain[2]);
        CertPath path = factory.generateCertPath(certList);
        MockProxyCertPathValidator validator = new MockProxyCertPathValidator(false, false, false, false);
        X509ProxyCertPathParameters parameters =
                new X509ProxyCertPathParameters(keyStore, certStore, policyStore, false, map);
        X509ProxyCertPathValidatorResult result =
                (X509ProxyCertPathValidatorResult) validator.engineValidate(path, parameters);
        // JGLOBUS-103
    }

    @Test
    public void validatePathBad() throws Exception {

        KeyStore keyStore = getKeyStore(null);

        X509Certificate[] chain;

        CertStore certStore = CertStore.getInstance("MockCertStore", null);
        TestPolicyStore policyStore = new TestPolicyStore(null);
        // proxy, CA
        chain = new X509Certificate[]{goodCertsArr[5], goodCertsArr[0]};
        validateError(chain, keyStore, certStore, policyStore, "Incorrect certificate path");

        // user, proxy, CA
        chain = new X509Certificate[]{goodCertsArr[1], goodCertsArr[2], goodCertsArr[0]};
        validateError(chain, keyStore, certStore, policyStore, "Incorrect certificate path");

        // user, user, CA
        chain = new X509Certificate[]{goodCertsArr[1], goodCertsArr[1], goodCertsArr[0]};
        validateError(chain, keyStore, certStore, policyStore, "Incorrect certificate path");

        // user, CA, user
        chain = new X509Certificate[]{goodCertsArr[1], goodCertsArr[0], goodCertsArr[1]};
        validateError(chain, keyStore, certStore, policyStore, "Incorrect certificate path");
    }

    @Test
    public void validatePathMixedProxy() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});

        X509Certificate[] chain;

        TestCertParameters certStoreParameters = new TestCertParameters(null, this.crls);

        CertStore certStore = CertStore.getInstance("MockCertStore", certStoreParameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);


        // GSI 3 PC, GSI 2 PC, EEC, CA
        chain = new X509Certificate[]{goodCertsArr[36], goodCertsArr[2], goodCertsArr[1], goodCertsArr[0]};
        validateError(chain, keyStore, certStore, policyStore,
                "Proxy certificate can only sign another proxy certificate of same type");

        // GSI 2 PC, GSI 3 PC, EEC, CA
        chain = new X509Certificate[]{goodCertsArr[35], goodCertsArr[5], goodCertsArr[1], goodCertsArr[0]};
        validateError(chain, keyStore, certStore, policyStore,
                "Proxy certificate can only sign another proxy certificate of same type");
    }

    @Test
    public void validatePathProxyPathConstraint() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});

        X509Certificate[] chain;

        TestCertParameters certStoreParameters = new TestCertParameters(null, this.crls);

        CertStore certStore = CertStore.getInstance("MockCertStore", certStoreParameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);

        // GSI 3 PC pathlen=0, GSI 3 PC, EEC, CA
        chain = new X509Certificate[]{goodCertsArr[11], goodCertsArr[1], goodCertsArr[0]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[1], false);

        // GSI 3 PC, GSI 3 PC pathlen=0, EEC, CA
        chain = new X509Certificate[]{goodCertsArr[32], goodCertsArr[11], goodCertsArr[1], goodCertsArr[0]};
        validateError(chain, keyStore, certStore, policyStore, "Proxy path length constraint violated");


        // GSI 3 PC, GSI 3 independent PC pathlen=1, EEC, CA
        chain = new X509Certificate[]{goodCertsArr[33], goodCertsArr[12], goodCertsArr[1], goodCertsArr[0]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[12], false);

        // GSI 3 PC, GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
        chain = new X509Certificate[]{goodCertsArr[34], goodCertsArr[33],
                goodCertsArr[12], goodCertsArr[1], goodCertsArr[0]};
        validateError(chain, keyStore, certStore, policyStore, "Proxy path length constraint violated");
    }

    @Test
    public void validatePathCAPathConstraint() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[16]});

        X509Certificate[] chain;

        TestCertParameters certStoreParameters = new TestCertParameters(null, this.crls);

        CertStore certStore = CertStore.getInstance("MockCertStore", certStoreParameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);


        // EEC, CA (pathlen=0)
        chain = new X509Certificate[]{goodCertsArr[15], goodCertsArr[16]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[15], false);

        // GSI 2 limited PC, EEC, CA (pathlen=0) , 3 not issued by this!
        // chain = new X509Certificate[]{goodCertsArr[3], goodCertsArr[15],
        //                               goodCertsArr[16]};
        // validateChain(chain, certStore, policyStore, goodCertsArr[15], true);

        // GSI 3 PC, EEC, CA (pathlen=0)
        chain = new X509Certificate[]{goodCertsArr[17], goodCertsArr[15], goodCertsArr[16]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[15], false);

        // GSI 3 PC, EEC, CA (pathlen=0), CA (pathlen=2), CA (pathlen=2)
        chain = new X509Certificate[]{goodCertsArr[17], goodCertsArr[15],
                goodCertsArr[16], goodCertsArr[13], goodCertsArr[13]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[15], false);

        // these should fail

        // EEC, CA (pathlen=0), CA (pathlen=0)
        // JGLOBUS-103  why should these fail, the CA is not subordinate. To really
        //  test this we might need CA certificates with subordinates and some
        // certificates issued incorrectly.
//        chain = new X509Certificate[]{goodCertsArr[15], goodCertsArr[16],
//                                      goodCertsArr[16]};
//        validateError(chain, certStore, policyStore,
//                      "ProxyPathValidatorException.PATH_LENGTH_EXCEEDED");

//        // GSI 2 limited PC, EEC, CA (pathlen=0), CA (pathlen=2), CA (pathlen=2), CA (pathlen=2)
//        chain = new X509Certificate[]{goodCertsArr[3], goodCertsArr[15],
//                                      goodCertsArr[16], goodCertsArr[13],
//                                      goodCertsArr[13], goodCertsArr[13]};
//        validateError(chain, certStore, policyStore,
//                      "ProxyPathValidatorException.PATH_LENGTH_EXCEEDED");

//        // GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
//        chain = new X509Certificate[]{goodCertsArr[10], goodCertsArr[12],
//                                      goodCertsArr[1], goodCertsArr[13]};
//        validateChain(chain, certStore, policyStore, goodCertsArr[10], false);
//
//        // GSI 3 PC, GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
//        chain = new X509Certificate[]{goodCertsArr[10], goodCertsArr[10],
//                                      goodCertsArr[12],
//                                      goodCertsArr[1], goodCertsArr[13]};
//        validateError(chain, certStore, policyStore,
//                      "ProxyPathValidatorException.PATH_LENGTH_EXCEEDED");
//
//        // GSI 3 PC, GSI 3 PC pathlen=0, EEC, CA
//        chain = new X509Certificate[]{goodCertsArr[10],
//                                      goodCertsArr[11],
//                                      goodCertsArr[1],
//                                      goodCertsArr[13]};
//        validateError(chain, certStore, policyStore,
//                      "ProxyPathValidatorException.FAILURE");
    }

    @Test
    public void testKeyUsage() throws Exception {

        X509Certificate[] certsArr = new X509Certificate[testCerts.length];
        for (int i = 0; i < certsArr.length; i++) {
            certsArr[i] = CertificateLoadUtil.loadCertificate(new ByteArrayInputStream(testCerts[i].getBytes()));
        }

        KeyStore keyStore = getKeyStore(new X509Certificate[]{certsArr[2]});


        TestCertParameters certStoreParameters = new TestCertParameters(null, this.crls);

        CertStore certStore = CertStore.getInstance("MockCertStore", certStoreParameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);


        X509Certificate[] chain;

        // certArr[1] - has key usage but certSign is off - but it sings proxy
        // certArr[2] - has key usage and certSing is on
        chain = new X509Certificate[]{certsArr[0], certsArr[1], certsArr[2]};
        validateChain(chain, keyStore, certStore, policyStore, certsArr[1],
                false);
    }

    @Test
    public void testNoBasicConstraintsExtension() throws Exception {

        KeyStore keyStore = getKeyStore(null);

        X509Certificate[] chain;
        CertStore certStore = CertStore.getInstance("MockCertStore", null);
        TestPolicyStore policyStore = new TestPolicyStore(null);

        // EEC, EEC, CA - that should fail
        chain = new X509Certificate[]{goodCertsArr[1], goodCertsArr[1],
                goodCertsArr[0]};
        validateError(chain, keyStore, certStore, policyStore,
                "Incorrect certificate path");


        keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[1]});

        TestCertParameters parameters =
                new TestCertParameters(null, null);

        // this makes the PathValidator think the chain is:
        // CA, CA, CA - which is ok.
        /*certStore = CertStore.getInstance("MockCertStore", parameters);
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[1],
                false);*/
    }

    @Test
    public void testCrlsChecks() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[1],
                goodCertsArr[16],
                goodCertsArr[25],
                goodCertsArr[21]});

        TestCertParameters parameters =
                new TestCertParameters(null, this.crls);
        CertStore certStore =
                CertStore.getInstance("MockCertStore", parameters);
        TestPolicyStore policyStore = new TestPolicyStore(null);

        // ca1 ca1user1 good chain
        X509Certificate[] chain =
                new X509Certificate[]{goodCertsArr[22], goodCertsArr[21]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[22],
                false);

        // ca1 ca1user2 good chain
        chain = new X509Certificate[]{goodCertsArr[23], goodCertsArr[21]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[23],
                false);

        // ca2 user1 bad chain
        chain = new X509Certificate[]{goodCertsArr[26], goodCertsArr[25]};
        validateError(chain, keyStore, certStore, policyStore, "revoked");

        // ca2 user2 bad chain
        chain = new X509Certificate[]{goodCertsArr[27], goodCertsArr[25]};
        validateError(chain, keyStore, certStore, policyStore, "revoked");

        // ca2 user3 good chain
        chain = new X509Certificate[]{goodCertsArr[28], goodCertsArr[25]};
        validateChain(chain, keyStore, certStore, policyStore, goodCertsArr[28],
                false);

        // ca2 user2 revoked CRL
        // The sleep statements here are to force a CRL refresh.
        chain = new X509Certificate[]{goodCertsArr[27], goodCertsArr[25]};
        String caCertLocations =
                CoGProperties.getDefault().getCaCertLocations();
        System.setProperty("X509_CERT_DIR", crlDir);
        Thread.sleep(100);
        validateErrorBuiltin(chain, keyStore, certStore, policyStore, "revoked");
        Thread.sleep(100);
        System.setProperty("X509_CERT_DIR", caCertLocations);
        validateChainBuiltin(chain, keyStore, certStore, policyStore);
    }

    @Test
    public void testSigningPolicy() throws Exception {

        KeyStore keyStore = getKeyStore(new X509Certificate[]{goodCertsArr[0]});


        TestCertParameters parameters =
                new TestCertParameters(null, null);
        CertStore certStore =
                CertStore.getInstance("MockCertStore", parameters);

        X509Certificate[] chain;
        SigningPolicyParser parser = new SigningPolicyParser();

        Reader reader = new StringReader(signingPolicy);
        Map<X500Principal, SigningPolicy> map =
                parser.parse(reader);


        TestPolicyStore policyStore = new TestPolicyStore(map);
        chain = new X509Certificate[]{goodCertsArr[1], goodCertsArr[0]};
        validateChainWithPolicy(chain, keyStore, certStore, policyStore,
                false);

        reader = new StringReader(signingPolicyViolation);
        map = parser.parse(reader);
        policyStore = new TestPolicyStore(map);
        validateChainWithPolicy(chain, keyStore, certStore, policyStore, true);

    }

    // for testing only to disable validity checking

    public class MockProxyCertPathValidator extends X509ProxyCertPathValidator {

        boolean checkCertificateDateValidity;
        boolean checkCRLDateValidity;
        boolean checkSigningPolicy;
        boolean useBuiltinCRL;
        private CertificateChecker dateChecker = new DateValidityChecker();

        public MockProxyCertPathValidator(boolean checkCertificateDateValidity_,
                                          boolean checkCRLDateValidity_,
                                          boolean checkSigningPolicy_,
                                          boolean useBuiltinCRL_) {

            this.checkCertificateDateValidity = checkCertificateDateValidity_;
            this.checkCRLDateValidity = checkCRLDateValidity_;
            this.checkSigningPolicy = checkSigningPolicy_;
            this.useBuiltinCRL = useBuiltinCRL_;
        }

        @Override
        protected List<CertificateChecker> getCertificateCheckers() {
            List<CertificateChecker> checkers = new ArrayList<CertificateChecker>();
            if (checkCertificateDateValidity) {
                checkers.add(dateChecker);
            }
            checkers.add(new UnsupportedCriticalExtensionChecker());
            checkers.add(new IdentityChecker(this));
            if (useBuiltinCRL) {
              CertificateRevocationLists crls = CertificateRevocationLists.getDefaultCertificateRevocationLists();
              checkers.add(new CRLChecker(crls, this.keyStore, this.checkCertificateDateValidity));
            } else {
              checkers.add(new CRLChecker(this.certStore, this.keyStore, this.checkCertificateDateValidity));
            }
            if (this.checkSigningPolicy) {
                checkers.add(new SigningPolicyChecker(this.policyStore));
            }
            return checkers;
        }
    }

    public class TestPolicyStore implements SigningPolicyStore {

        Map<X500Principal, SigningPolicy> policies;

        public TestPolicyStore(Map<X500Principal, SigningPolicy> policies_)
                throws InvalidAlgorithmParameterException {

            this.policies = policies_;
        }

        public SigningPolicy getSigningPolicy(X500Principal caPrincipal)
                throws SigningPolicyStoreException {
            return this.policies.get(caPrincipal);
        }
    }

    public class TestCertParameters implements CertStoreParameters {

        X509Certificate[] certificates;
        X509CRL[] crls;

        public TestCertParameters(X509Certificate[] certificates_,
                                  X509CRL[] crls_) {
            this.certificates = certificates_;
            this.crls = crls_;
        }

        public X509Certificate[] getCertificates() {
            return certificates;
        }

        public X509CRL[] getCRLs() {
            return this.crls;
        }

        public Object clone() {
            try {
                return super.clone();
            } catch (CloneNotSupportedException e) {
                throw new InternalError(e.getLocalizedMessage());
            }

        }
    }


}
