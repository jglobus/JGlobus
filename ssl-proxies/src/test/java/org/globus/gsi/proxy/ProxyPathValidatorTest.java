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
package org.globus.gsi.proxy;

import org.globus.common.CoGProperties;

import org.globus.gsi.util.CertificateLoadUtil;

import org.globus.gsi.trustmanager.CRLChecker;
import org.globus.gsi.trustmanager.CertificateChecker;
import org.globus.gsi.trustmanager.DateValidityChecker;
import org.globus.gsi.trustmanager.IdentityChecker;
import org.globus.gsi.trustmanager.SigningPolicyChecker;
import org.globus.gsi.trustmanager.UnsupportedCriticalExtensionChecker;
import org.globus.gsi.trustmanager.X509ProxyCertPathValidator;

import org.globus.gsi.X509Credential;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPath;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.TrustedCertificates;
import org.globus.gsi.SigningPolicy;
import org.globus.gsi.SigningPolicyParser;
import org.globus.gsi.CertificateRevocationLists;
import org.globus.gsi.proxy.ProxyPolicyHandler;
import org.globus.gsi.proxy.ProxyPathValidator;
import org.globus.gsi.proxy.ProxyPathValidatorException;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyPolicy;

import junit.framework.TestCase;

public class ProxyPathValidatorTest extends TestCase {

    private static Log log = LogFactory.getLog(ProxyPathValidatorTest.class);
    public static final String BASE = "validatorTest/";

    public static String[] crlNames = { "ca2crl.r0", "testca3.r0" };

    public static String[][] certs = {
        {GSIConstants.CertificateType.CA.name(), "TestCA1.pem"},
        {GSIConstants.CertificateType.EEC.name(), "eecFromTestCA1.pem"},
        {GSIConstants.CertificateType.GSI_2_PROXY.name(), "gsi2fullproxy.pem"},
        {GSIConstants.CertificateType.GSI_2_LIMITED_PROXY.name(), "gsi2limitedproxy.pem"},
            // 4, double GSIConstants.CertificateType.GSI_2_LIMITED_PROXY), gsi2limited2xproxy.pem (issued by
            // 3)
        {GSIConstants.CertificateType.GSI_2_LIMITED_PROXY.name(), "gsi2limited2xproxy.pem"},
            // 5, GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY), gsi3impersonationproxy.pem
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3impersonationproxy.pem"},
            // 6, GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY), gsi3independentproxy.pem
        {GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY.name(), "gsi3independentproxy.pem"},
            // 7, GSIConstants.CertificateType.GSI_3_LIMITED_PROXY), gsi3limitedproxy.pem
        {GSIConstants.CertificateType.GSI_3_LIMITED_PROXY.name(), "gsi3limitedproxy.pem"},
            // 8, GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY), gsi3restrictedproxy.pem
        {GSIConstants.CertificateType.GSI_3_RESTRICTED_PROXY.name(), "gsi3restrictedproxy.pem"},
            // double
            // 9, GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY), gsi3impersonation2xproxy.pem
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3impersonation2xproxy.pem"},
            // 10, GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY), gsi3independent2xproxy.pem
        {GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY.name(), "gsi3independent2xproxy.pem"},
            // pathLen = 0
            // 11, GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY), gsi3impersonationp0proxy.pem
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3impersonationp0proxy.pem"},
            // pathLen = 1
            // 12, GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY), gsi2independentp1proxy.pem
        {GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY.name(), "gsi3independentp1proxy.pem"},
            // pathLen = 2
            // 13, GSIConstants.CertificateType.CA),
        {GSIConstants.CertificateType.CA.name(), "testca.pem"},
            // 14, GSIConstants.CertificateType.EEC)
        {GSIConstants.CertificateType.EEC.name(), "testeec1.pem"},
            // 15, GSIConstants.CertificateType.EEC)
        {GSIConstants.CertificateType.EEC.name(), "testeec2.pem"},
            // pathLen = 1
            // 16, GSIConstants.CertificateType.CA)
        {GSIConstants.CertificateType.CA.name(), "testca2.pem"}, // crl for this, 16
            // 17, GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY),
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "testgsi3proxy.pem"},
            // for CRL test
            // 18, GSIConstants.CertificateType.CA),
        {GSIConstants.CertificateType.CA.name(), "testca3.pem"},
            // 19, GSIConstants.CertificateType.EEC),
        {GSIConstants.CertificateType.EEC.name(), "crl_usercert.pem"},
            // 20, GSIConstants.CertificateType.GSI_2_PROXY),
        {GSIConstants.CertificateType.GSI_2_PROXY.name(), "crl_proxy.pem"},
            // 21 (all good)
            // GSIConstants.CertificateType.CA)
        {GSIConstants.CertificateType.CA.name(), "ca1cert.pem"},
            // 22, GSIConstants.CertificateType.EEC
        {GSIConstants.CertificateType.EEC.name(), "user1ca1.pem"},
            // 23, GSIConstants.CertificateType.EEC)
        {GSIConstants.CertificateType.EEC.name(), "user2ca1.pem"},
            // 24, GSIConstants.CertificateType.EEC)
        {GSIConstants.CertificateType.EEC.name(), "user3ca1.pem"},
            // 25
            // GSIConstants.CertificateType.CA)
        {GSIConstants.CertificateType.CA.name(), "ca2cert.pem"}, // crl 25
            // must be revoked (in ca2crl.r0)
            // 26, GSIConstants.CertificateType.EEC)
        {GSIConstants.CertificateType.EEC.name(), "user1ca2.pem"},
            // must be revoked (in ca2crl.r0)
            // 27, GSIConstants.CertificateType.EEC),
        {GSIConstants.CertificateType.EEC.name(), "user2ca2.pem"},
            // 28, GSIConstants.CertificateType.EEC)
        {GSIConstants.CertificateType.EEC.name(), "user3ca2.pem"},
            // 29
            // gsi3 limited impersonation signs a gsi3 independent
        {GSIConstants.CertificateType.GSI_3_INDEPENDENT_PROXY.name(), "gsi3independentFromLimitedProxy.pem"},
            // 30
            // gsi3 limited impersonation signs a gsi3 impersonation
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3limitedimpersonation2xproxy.pem"},
            // 31
            // gsi3 independent signs a gsi3 impersonation
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3impersonationFromIndependentProxy.pem"},
            // 32
            // gsi3 pathlength 0 impersonatipon proxy signs proxy
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3FromPathZeroProxy.pem"},
            // 33
            // gsi3 path length 1 independent proxy signs proxy
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3FromPathOneProxy.pem"},
            // 34
            // gsi3FrompathOneProxy signs proxy
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3FromPathOneIssuedProxy.pem"},
            // 35
            // gsi2 proxy generated from gsi3impersonationProxy
        {GSIConstants.CertificateType.GSI_2_PROXY.name(), "gsi2proxyFromgsi3.pem"},
            // 36
            // gsi3 proxy generated from gsi2fullproxy
        {GSIConstants.CertificateType.GSI_3_IMPERSONATION_PROXY.name(), "gsi3proxyFromgsi2.pem" }};

    public static String[] badCerts = {
            "-----BEGIN CERTIFICATE-----\n" + "MIICFTCCAX6gAwIBAgIDClb3MA0GCSqGSIb3DQEBBAUAMGIxCzAJBgNVBAYTAlVT\n"
                + "MQ8wDQYDVQQKEwZHbG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFi\n"
                + "b3JhdG9yeTEMMAoGA1UECxMDTUNTMQ4wDAYDVQQDEwVnYXdvcjAeFw0wMjEyMTgw\n"
                + "NzEzNDhaFw0wMjEyMTgxOTE4NDhaMIGCMQswCQYDVQQGEwJVUzEPMA0GA1UEChMG\n"
                + "R2xvYnVzMSQwIgYDVQQKExtBcmdvbm5lIE5hdGlvbmFsIExhYm9yYXRvcnkxDDAK\n"
                + "BgNVBAsTA01DUzEOMAwGA1UEAxMFZ2F3b3IxDjAMBgNVBAMTBXByb3h5MQ4wDAYD\n"
                + "VQQDEwVwcm94eTBaMA0GCSqGSIb3DQEBAQUAA0kAMEYCQQCplfu3OZH5AfYgoYKi\n"
                + "KFmGZnbj3+ZwJm45B6Ef7qwW7Le7FP4eirljObqijgn8ao0gGqy38LYbaTntToqX\n"
                + "iy5fAgERMA0GCSqGSIb3DQEBBAUAA4GBAKnNy0VPDzzD6++7i9a/yegPX2+OVI6C\n"
                + "7oss1/4sSw2gfn/q8qNiGdt1kr4W3JJACdjgnik8fokNS7pDMdXKi3Wx6E0HhgKz\n"
                + "eRIm5r6Vj7nshVBAv60Xmfju3yaOZsDnj8p0t8Fjc8ekeZowLEdRn7PCEQPylMOp\n" + "2puR03MaPiFj\n"
                + "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n" + "MIICBDCCAW2gAwIBAgIDAx4rMA0GCSqGSIb3DQEBBAUAMGIxCzAJBgNVBAYTAlVT\n"
                + "MQ8wDQYDVQQKEwZHbG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFi\n"
                + "b3JhdG9yeTEMMAoGA1UECxMDTUNTMQ4wDAYDVQQDEwVnYXZvcjAeFw0wMjEyMTgw\n"
                + "NzIxMThaFw0wMjEyMTgxOTI2MThaMHIxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKEwZH\n"
                + "bG9idXMxJDAiBgNVBAoTG0FyZ29ubmUgTmF0aW9uYWwgTGFib3JhdG9yeTEMMAoG\n"
                + "A1UECxMDTUNTMQ4wDAYDVQQDEwVnYXdvcjEOMAwGA1UEAxMFcHJveHkwWjANBgkq\n"
                + "hkiG9w0BAQEFAANJADBGAkEAx2fp80b+Yo0zCwjYJdIjzn0N3ezzcD2h2bAr/Nop\n"
                + "w/H6JB4heiVGMeydMlSJHyI7J/s5l8k39G/KVrBGT9tRJwIBETANBgkqhkiG9w0B\n"
                + "AQQFAAOBgQCRRvTdW6Ddn1curWm515l/GoAoJ76XBFJWfusIZ9TdwE8hlkRpK9Bd\n"
                + "Rrao4Z2YO+e3UItn45Hs+8gzx+jBB1AduTUor603Z8AXaNbF/c+gz62lBWlcmZ2Y\n"
                + "LzuUWgwZLd9HdA2YBgCcT3B9VFmBxcnPjGOwWT29ZUtyy2GXFtzcDw==\n"
                + "-----END CERTIFICATE-----" };

    public static String[] testCerts = {
            "-----BEGIN CERTIFICATE-----\n"
                + "MIIB7zCCAVigAwIBAgICAbowDQYJKoZIhvcNAQEEBQAwVzEbMBkGA1UEChMSZG9l\n"
                + "c2NpZW5jZWdyaWQub3JnMQ8wDQYDVQQLEwZQZW9wbGUxJzAlBgNVBAMTHlZpamF5\n"
                + "YSBMYWtzaG1pIE5hdGFyYWphbiAxNzkwODAeFw0wMzAxMTcyMjExMjJaFw0wMzAx\n"
                + "MTgxMDE2MjJaMGcxGzAZBgNVBAoTEmRvZXNjaWVuY2VncmlkLm9yZzEPMA0GA1UE\n"
                + "CxMGUGVvcGxlMScwJQYDVQQDEx5WaWpheWEgTGFrc2htaSBOYXRhcmFqYW4gMTc5\n"
                + "MDgxDjAMBgNVBAMTBXByb3h5MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANGP+xct\n"
                + "lDYMPm11QKnACvqs95fbPRehvUi6/dizZ+VrDOU1OTUoXA0t6HRgtmJ8XthEUKxU\n"
                + "MVsxjXtoZOzfuFECAwEAATANBgkqhkiG9w0BAQQFAAOBgQBqFTcN/qqvTnyI4z26\n"
                + "lv1lMTuRIjL9l6Ug/Kwxuzjpl088INky1myFPjKsWMYzh9nXIQg9gg2dJTno5JHB\n"
                + "++u0Fw2iNrTjswu4hvqYZn+LoSGchH2XyCUssuOWCbW4IkN8/Xzfre2oC2EieECC\n"
                + "w+jjGhcqPrxvkHh8xXYroqA0Sg==\n"
                + "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n"
                + "MIIDLDCCAhSgAwIBAgICAbowDQYJKoZIhvcNAQEFBQAwdTETMBEGCgmSJomT8ixk\n"
                + "ARkWA25ldDESMBAGCgmSJomT8ixkARkWAmVzMSAwHgYDVQQLExdDZXJ0aWZpY2F0\n"
                + "ZSBBdXRob3JpdGllczEZMBcGA1UECxMQRE9FIFNjaWVuY2UgR3JpZDENMAsGA1UE\n"
                + "AxMEcGtpMTAeFw0wMjA5MjMyMzQ2NDRaFw0wMzA5MjMyMzQ2NDRaMFcxGzAZBgNV\n"
                + "BAoTEmRvZXNjaWVuY2VncmlkLm9yZzEPMA0GA1UECxMGUGVvcGxlMScwJQYDVQQD\n"
                + "Ex5WaWpheWEgTGFrc2htaSBOYXRhcmFqYW4gMTc5MDgwgZ8wDQYJKoZIhvcNAQEB\n"
                + "BQADgY0AMIGJAoGBAORYHsPQU3yVlTsC/29CDoEYF82PVlolQk5s+1m6A7m3VvML\n"
                + "TKh4ja6cKtq7C5rBUIWdyklkU3eXSSmiAzjJrVOmfWK3RR465A5tfvJLmXKWaq3U\n"
                + "7SvI6v3vx4Jzy4MJs46TDAr4v9JRJG2yshoxruRy2gDsn4F5NfLLevDNwzSLAgMB\n"
                + "AAGjaDBmMBEGCWCGSAGG+EIBAQQEAwIF4DAOBgNVHQ8BAf8EBAMCBPAwHwYDVR0j\n"
                + "BBgwFoAUVBeIygPBOSa4VabEmfQrAqu+AOkwIAYDVR0RBBkwF4EVdmlqYXlhbG5A\n"
                + "bWF0aC5sYmwuZ292MA0GCSqGSIb3DQEBBQUAA4IBAQC/dxf5ZuSrNrxslHUZfDle\n"
                + "V8SPnX5roBUOuO2EPpEGYHB25Ca+TEi0ra0RSRuZfGmY13/aS6CzjBF+6GED9MLo\n"
                + "6UdP1dg994wpGZ2Mj0dZoGE7we10NrSvFAS3u7uXrTTegeJoDpo1k9YVsOkK9Lu9\n"
                + "Sg+EztnMGa1BANWf779Qws5J9xUR2Nip0tBkV3IRORcBx0CoZzQnDIWyppmnkza2\n"
                + "mhgEv6CXYYB4ucCFst0P2Q3omcWrtHexoueMGOV6PtLFBst5ReOaZWU+q2D30t3b\n"
                + "GFITa0aayXTlb6gWgo3z/O/K5GZS5jF+BA3j1e8IhxqeibT1rVHF4W4ZMjGhBcwa\n"
                + "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n"
                + "MIIEqjCCBBOgAwIBAgIBLzANBgkqhkiG9w0BAQUFADBbMRkwFwYDVQQKExBET0Ug\n"
                + "U2NpZW5jZSBHcmlkMSAwHgYDVQQLExdDZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEc\n"
                + "MBoGA1UEAxMTQ2VydGlmaWNhdGUgTWFuYWdlcjAeFw0wMTEyMjEyMzQ4MzdaFw0w\n"
                + "NDAxMTAyMzQ4MzdaMHUxEzARBgoJkiaJk/IsZAEZFgNuZXQxEjAQBgoJkiaJk/Is\n"
                + "ZAEZFgJlczEgMB4GA1UECxMXQ2VydGlmaWNhdGUgQXV0aG9yaXRpZXMxGTAXBgNV\n"
                + "BAsTEERPRSBTY2llbmNlIEdyaWQxDTALBgNVBAMTBHBraTEwggEiMA0GCSqGSIb3\n"
                + "DQEBAQUAA4IBDwAwggEKAoIBAQDhgzoAt5viFffXWG6P0KSf/dO0mrEbgpuKIHDa\n"
                + "RdHkxJGaoBgRO2D+YV4Wh+JcKlz64v2ScYHCgGbKoaE+cGM/O06xkLCV0pyT4Xvj\n"
                + "6/R80jqwzzRw8aYz9iE/wjljK1ehb+oJ6TJlnotCVBd7TlHODYfXXblt67/Uk1uu\n"
                + "4l17jCdfk4mUn/2Bdeae4EMibj7Vc1dkPkyY47ZADTeFXMNDyp4yGFeIDZQ6h+YH\n"
                + "27+t1/TDuEH1R4PpklRpSbppGprI8hv2P6uEKTySjAEkww9xVzenN6oULeafFJuS\n"
                + "t6Ui6BFxc1OuxMq/s0PDiFh8bPMhzJWBfzaNPHnYrFDWcDwHAgMBAAGjggHeMIIB\n"
                + "2jAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFFQXiMoDwTkmuFWmxJn0KwKrvgDp\n"
                + "MB8GA1UdIwQYMBaAFJvOT/K8vVhwMdXyMg5+nr3iURTnMA8GA1UdEwEB/wQFMAMB\n"
                + "Af8wgY8GA1UdHwSBhzCBhDCBgaAaoBiGFmh0dHA6Ly9lbnZpc2FnZS5lcy5uZXSB\n"
                + "AgDsol+kXTBbMRkwFwYDVQQKExBET0UgU2NpZW5jZSBHcmlkMSAwHgYDVQQLExdD\n"
                + "ZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEcMBoGA1UEAxMTQ2VydGlmaWNhdGUgTWFu\n"
                + "YWdlcjCB5AYDVR0gBIHcMIHZMIHWBgoqhkiG90wDBgQBMIHHMF8GCCsGAQUFBwIC\n"
                + "MFMwJhYfRVNuZXQgKEVuZXJneSBTY2llbmNlcyBOZXR3b3JrKTADAgEBGilFU25l\n"
                + "dC1ET0UgU2NpZW5jZSBHcmlkIENlcnRpZmljYXRlIFBvbGljeTBkBggrBgEFBQcC\n"
                + "ARZYaHR0cDovL2VudmlzYWdlLmVzLm5ldC9FbnZpc2FnZSUyMERvY3MvRE9FU0cl\n"
                + "MjBDQSUyMENlcnRpZmljYXRlJTIwUG9saWN5JTIwYW5kJTIwQ1BTLnBkZjANBgkq\n"
                + "hkiG9w0BAQUFAAOBgQCaAdUregqwmCJG6j/h6uK2bTpcfa/SfpaYwsTy+zlf5r4P\n"
                + "iY/wIRN0ZjJ4RrJQ/WUH16onNwb87JnYe0V4JYhATAOnp/5y9kl+iC4XvHBioVxm\n"
                + "3sEADL40WAVREWBGZnyFqysXAEGfk+Wg7um5FzCwi6380GASKY0VujQG03f6Pg==\n"
                + "-----END CERTIFICATE-----"
            };

    // Globus CA signing policy. Using globusca.pem and usercert.pem
    public static String signingPolicy = "access_id_CA      X509         '/C=TestCA1/CN=CA'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/*\"'";

    // Globus CA signing policy that causes usercert.pem to violate
    // the policy
    public static String signingPolicyViolation = "access_id_CA      X509         '/C=TestCA1/CN=CA'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/12*\"'";

    // Globus CA signing policy without relevant signing policy
    public static String signingPolicySansPolicy = "# Globus CA rights\naccess_id_CA      nonX509         '/C=US/O=Globus/CN=Globus Certification Authority'\npos_rights        globus        CA:sign\ncond_subjects     globus       '\"/C=usa/O=Globus/*\"  \"/C=USA/O=Globus/*\"'\n# End of ca-signing-policy.conf";

    public static X509Certificate[] goodCertsArr;

    static {
        try {
            goodCertsArr = initCerts();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load certs: " + e.getMessage());
        }
    }

    public ProxyPathValidatorTest(String name) {
        super(name);
    }

    public static X509Certificate[] initCerts() throws Exception {
        CoGProperties.getDefault().setProperty(CoGProperties.getDefault().CRL_CACHE_LIFETIME, "1");

        X509Certificate[] goodCertsArr = new X509Certificate[certs.length];
        ClassLoader loader = ProxyPathValidatorTest.class.getClassLoader();
        for (int i = 0; i < certs.length; i++) {
            String name = BASE + certs[i][1];
            InputStream in = loader.getResourceAsStream(name);
            if (in == null) {
                throw new Exception("Unable to load: " + name);
            }
            log.debug("goodCertsArr[" + i + "]" + name);
            goodCertsArr[i] = CertificateLoadUtil.loadCertificate(in);
        }
        return goodCertsArr;
    }

    public void testValidateGsi2PathGood() throws Exception {

        X509Certificate[] chain = null;
        X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[0] };

        // EEC, CA
        chain = new X509Certificate[] { goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[1], false);

        // proxy, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[2], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[1], false);

        // limited proxy, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[3], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[1], true);

        // double limited proxy, limited proxy, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[4], goodCertsArr[3], goodCertsArr[1], goodCertsArr[0] };

        validateChain(chain, trustedCerts, goodCertsArr[1], true);
    }

    public void testValidateGsi3PathGood() throws Exception {

        X509Certificate[] chain = null;
        X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[0] };

        // GSI 3 PC impersonation, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[5], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[1], false);

        // GSI 3 PC independent, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[6], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[6], false);

        // GSI 3 PC imperson limited, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[7], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[1], true);

        // GSI 3 PC impersonation, GSI 3 PC limited impersonation, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[30], goodCertsArr[7], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[1], true);

        // GSI 3 PC impersonation, GSI 3 PC impersonation, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[9], goodCertsArr[5], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[1], false);

        // GSI 3 PC indepedent, GSI 3 PC independent, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[10], goodCertsArr[6], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[10], false);

        // GSI 3 PC impersonation, GSI 3 PC independent, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[31], goodCertsArr[6], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[6], false);

        // GSI 3 PC indepedent, GSI 3 PC limited impersonation, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[29], goodCertsArr[7], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[29], false);
    }

    public void testValidatePathWithRestrictedProxy() throws Exception {

        X509Certificate[] chain = null;
        X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[0] };

        // GSI 3 PC restricted, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[8], goodCertsArr[1], goodCertsArr[0] };
        validateError(chain, trustedCerts, ProxyPathValidatorException.UNKNOWN_POLICY);

        // // GSI 3 PC impersonation, GSI 3 PC restricted, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[9], goodCertsArr[8], goodCertsArr[1], goodCertsArr[0] };
        validateError(chain, trustedCerts, ProxyPathValidatorException.UNKNOWN_POLICY);

        TestProxyPathValidator v = new TestProxyPathValidator();
        v.setProxyPolicyHandler("1.3.6.1.4.1.3536.1.1.1.8", new ProxyPolicyHandler() {
            public void validate(ProxyCertInfo info, CertPath path, int index) throws CertPathValidatorException {
                ProxyPolicy policy = info.getProxyPolicy();
                String pol = policy.getPolicyAsString();
                assertEquals("<AllPermissions...>\r\n".trim(), pol.trim());
                // COMMENT fails without trimming
            }
        });
        chain = new X509Certificate[] { goodCertsArr[8], goodCertsArr[1], goodCertsArr[0] };
        v.validate(chain, trustedCerts);
    }

    public void testValidatePathBad() throws Exception {
        X509Certificate[] chain = null;
        X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[0] };

        // proxy, CA
        chain = new X509Certificate[] { goodCertsArr[5], goodCertsArr[0] };
        validateChain(chain, trustedCerts);

        // user, proxy, CA
        chain = new X509Certificate[] { goodCertsArr[1], goodCertsArr[2], goodCertsArr[0] };
        validateChain(chain, trustedCerts);

        // user, user, CA
        chain = new X509Certificate[] { goodCertsArr[1], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts);

        // user, CA, user
        chain = new X509Certificate[] { goodCertsArr[1], goodCertsArr[0], goodCertsArr[1] };
        validateChain(chain, trustedCerts);
    }

    public void testValidatePathMixedProxy() throws Exception {
        X509Certificate[] chain = null;
        X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[0] };

        // GSI 3 PC, GSI 2 PC, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[6], goodCertsArr[2], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts);

        // GSI 2 PC, GSI 3 PC, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[2], goodCertsArr[6], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts);
    }

    public void testValidatePathProxyPathConstraint() throws Exception {
        X509Certificate[] chain = null;
        X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[0] };

        // GSI 3 PC pathlen=0, GSI 3 PC, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[11], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[1], false);

        // GSI 3 PC, GSI 3 PC pathlen=0, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[32], goodCertsArr[11], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts);

        // GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[33], goodCertsArr[12], goodCertsArr[1], goodCertsArr[0] };
        validateChain(chain, trustedCerts, goodCertsArr[12], false);

        // GSI 3 PC, GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[34], goodCertsArr[33], goodCertsArr[12], goodCertsArr[1],
                goodCertsArr[0] };
        validateError(chain, trustedCerts, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);
    }

    public void testValidatePathCAPathConstraint() throws Exception {
        X509Certificate[] chain = null;
        X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[16] };

        // should all be OK

        // EEC, CA (pathlen=0)
        chain = new X509Certificate[] { goodCertsArr[15], goodCertsArr[16] };
        validateChain(chain, trustedCerts, goodCertsArr[15], false);

        // GSI 2 limited PC, EEC, CA (pathlen=0)
        chain = new X509Certificate[] { goodCertsArr[3], goodCertsArr[15], goodCertsArr[16] };
        //validateChain(chain, trustedCerts, goodCertsArr[15], true);
        validateError(chain, trustedCerts, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);

        // GSI 3 PC, EEC, CA (pathlen=0)
        chain = new X509Certificate[] { goodCertsArr[17], goodCertsArr[15], goodCertsArr[16] };
        validateChain(chain, trustedCerts, goodCertsArr[15], false);

        // GSI 3 PC, EEC, CA (pathlen=0), CA (pathlen=2), CA (pathlen=2)
        chain = new X509Certificate[] { goodCertsArr[17], goodCertsArr[15], goodCertsArr[16], goodCertsArr[13],
                goodCertsArr[13] };
        validateChain(chain, trustedCerts, goodCertsArr[15], false);

        // these should fail

        // EEC, CA (pathlen=0), CA (pathlen=0)
        chain = new X509Certificate[] { goodCertsArr[15], goodCertsArr[16], goodCertsArr[16] };
        validateError(chain, trustedCerts, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);

        // GSI 2 limited PC, EEC, CA (pathlen=0), CA (pathlen=2), CA (pathlen=2), CA (pathlen=2)
        chain = new X509Certificate[] { goodCertsArr[3], goodCertsArr[15], goodCertsArr[16], goodCertsArr[13],
               goodCertsArr[13], goodCertsArr[13] };
        validateError(chain, trustedCerts, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);

        // GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[10/*10*/], goodCertsArr[12], goodCertsArr[1], goodCertsArr[13] };
        //validateChain(chain, trustedCerts, goodCertsArr[10/*10*/], false);
        validateError(chain, trustedCerts, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);

        // GSI 3 PC, GSI 3 PC, GSI 3 PC pathlen=1, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[10], goodCertsArr[10], goodCertsArr[12], goodCertsArr[1],
                goodCertsArr[13] };
        validateError(chain, trustedCerts, ProxyPathValidatorException.PATH_LENGTH_EXCEEDED);

        // GSI 3 PC, GSI 3 PC pathlen=0, EEC, CA
        chain = new X509Certificate[] { goodCertsArr[10], goodCertsArr[11], goodCertsArr[1], goodCertsArr[13] };
        validateError(chain, trustedCerts, ProxyPathValidatorException.FAILURE);
    }

    public void testKeyUsage() throws Exception {
        X509Certificate[] certsArr = new X509Certificate[testCerts.length];

        for (int i = 0; i < certsArr.length; i++) {
            certsArr[i] = CertificateLoadUtil.loadCertificate(
                new ByteArrayInputStream(testCerts[i].getBytes()));
        }
        X509Certificate[] trustedCAs = new X509Certificate[]{certsArr[2]};
        X509Certificate[] chain = null;

        // certArr[1] - has key usage but certSign is off - but it signs proxy
        // certArr[2] - has key usage and certSign is on
        chain = new X509Certificate[] { certsArr[0], certsArr[1], certsArr[2] };
        validateChain(chain, trustedCAs, certsArr[1], false);

        TestProxyPathValidator v = new TestProxyPathValidator();
        v.validate(chain, new TrustedCertificates(trustedCAs));
        assertEquals(false, v.isLimited());
        assertEquals(certsArr[1], v.getIdentityCertificate());

    }

    public void testNoBasicConstraintsExtension() throws Exception {
        X509Certificate[] chain = null;
        X509Certificate[] trustedCAs = new X509Certificate[] { goodCertsArr[16] };
        X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[16] };
        // EEC, EEC, CA - that should fail
        //chain = new X509Certificate[] { goodCertsArr[1], goodCertsArr[1], goodCertsArr[0] };
        chain = new X509Certificate[] { goodCertsArr[15], goodCertsArr[15], goodCertsArr[16] };
        //validateChain(chain, trustedCerts, goodCertsArr[15], false);

        validateChain(chain, trustedCAs);


        TestProxyPathValidator v = new TestProxyPathValidator();
        TrustedCertificates trustedCert = new TrustedCertificates(new X509Certificate[] { goodCertsArr[16] },
            new SigningPolicy[] { new SigningPolicy(new X500Principal("CN=foo"), new String[] { "CN=foo" }) });

        //X509Certificate[] trustedCerts = new X509Certificate[] { goodCertsArr[1] };
        chain = new X509Certificate[] { goodCertsArr[16], goodCertsArr[16], goodCertsArr[0] };
        // this makes the PathValidator think the chain is:
        // CA, CA, CA - which is ok. irrelevant to signing policy.
        try {

            v.validate(chain, trustedCert);

        } catch (ProxyPathValidatorException e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    //JGLOBUS-103
    public void testCrlsChecks() throws Exception {

        TestProxyPathValidator tvalidator = new TestProxyPathValidator();

        // chain of good certs
        X509Certificate[] chain = new X509Certificate[]{goodCertsArr[22], goodCertsArr[21]};
        X509Certificate[] tCerts = new X509Certificate[]{goodCertsArr[1],
            goodCertsArr[16], goodCertsArr[25], goodCertsArr[21]};
        ClassLoader loader = ProxyPathValidatorTest.class.getClassLoader();
        String location1 = loader.getResource(BASE).getPath();
        CertificateRevocationLists certRevLists = CertificateRevocationLists.getCertificateRevocationLists(location1);
        assertNotNull(certRevLists);
        assertEquals(2,certRevLists.getCrls().length);

        TrustedCertificates trustedCerts = new TrustedCertificates(tCerts);
        X509CRL[] crls = certRevLists.getCrls();
        assertNotNull(crls);
        assertEquals(2, crls.length);
        try {
            tvalidator.validate(chain, trustedCerts.getCertificates(), certRevLists, trustedCerts.getSigningPolicies());
        } catch (ProxyPathValidatorException e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e.getMessage());
        }

        tvalidator.reset();

        // remove signing policy checks and validity checks

        // ca1 ca1user1 good chain
        chain = new X509Certificate[] { goodCertsArr[22], goodCertsArr[21] };
        certRevLists = CertificateRevocationLists.getCertificateRevocationLists(location1);
        assertNotNull(certRevLists.getCrls());
        assertEquals(2,certRevLists.getCrls().length);

        try {
            tvalidator.validate(chain, new X509Certificate[] { goodCertsArr[21] }, certRevLists, trustedCerts
                .getSigningPolicies());
        } catch (ProxyPathValidatorException e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e.getMessage());
        }

        tvalidator.reset();

        // ca1 ca1user2 good chain
        chain = new X509Certificate[] { goodCertsArr[23], goodCertsArr[21] };
        try {
            tvalidator.validate(chain, new X509Certificate[] { goodCertsArr[21] }, certRevLists, trustedCerts
                .getSigningPolicies());
        } catch (ProxyPathValidatorException e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e.getMessage());
        }

        tvalidator.reset();

        // ca2 user1 bad chain
        chain = new X509Certificate[] { goodCertsArr[26], goodCertsArr[25] };
        try {
            tvalidator.validate(chain, new X509Certificate[] { goodCertsArr[25] }, certRevLists, trustedCerts
                .getSigningPolicies());
            fail("Validation did not throw exception");
        } catch (ProxyPathValidatorException crlExp) {
            // COMMENT no check on exception error code
            //assertEquals(ProxyPathValidatorException.REVOKED, crlExp.getErrorCode());
        }

        tvalidator.reset();

        // ca2 user2 bad chain
        chain = new X509Certificate[] { goodCertsArr[27], goodCertsArr[25] };
        try {
            tvalidator.validate(chain, new X509Certificate[] { goodCertsArr[25] }, certRevLists, trustedCerts
                .getSigningPolicies());
            fail("Validation did not throw exception");
        } catch (ProxyPathValidatorException crlExp) {
            // COMMENT no check on exceptino error code
            //assertEquals(ProxyPathValidatorException.REVOKED, crlExp.getErrorCode());
        }

        tvalidator.reset();

        // ca2 user3 good chain
        chain = new X509Certificate[] { goodCertsArr[28], goodCertsArr[25] };
        try {
            tvalidator.validate(chain, new X509Certificate[] { goodCertsArr[25] }, certRevLists, trustedCerts.getSigningPolicies());
        } catch (ProxyPathValidatorException e) {
            e.printStackTrace();
            fail("Unexpected exception: " + e.getMessage());
        }
    }

    public void testSigningPolicy() throws Exception {

        X509Certificate[] chain = null;

        Map<X500Principal, SigningPolicy> map = new SigningPolicyParser().parse(new StringReader(signingPolicy));
        SigningPolicy policy = map.values().iterator().next();
        assertNotNull(policy);

        TestProxyPathValidator tvalidator = new TestProxyPathValidator(true);
        chain = new X509Certificate[] { goodCertsArr[1], goodCertsArr[0] };
        TrustedCertificates tc = new TrustedCertificates(new X509Certificate[] { goodCertsArr[0] },
            new SigningPolicy[] { policy });
        tvalidator.validate(chain, tc);

        map = new SigningPolicyParser().parse(new StringReader(signingPolicyViolation));
        policy = map.values().iterator().next();
        assertNotNull(policy);
        tc = new TrustedCertificates(new X509Certificate[] { goodCertsArr[0] }, new SigningPolicy[] { policy });

        try {
            tvalidator.validate(chain, tc);
            fail("Exception expected");
        } catch (ProxyPathValidatorException exp) {
            // COMMENT ignore error code
            //assertEquals(ProxyPathValidatorException.SIGNING_POLICY_VIOLATION, exp.getErrorCode());
        }

        try {
            map = new SigningPolicyParser().parse(new StringReader(signingPolicySansPolicy));
            fail("Exception expected");
        } catch (IllegalArgumentException exp) {
        }
    }

    private void validateChain(X509Certificate[] chain, X509Certificate[] trustedCerts) throws Exception {
        validateError(chain, trustedCerts, ProxyPathValidatorException.FAILURE);
    }

    private void validateChain(X509Certificate[] chain, X509Certificate[] trustedCerts,
        X509Certificate expectedIdentity, boolean expectedLimited) throws Exception {
        TestProxyPathValidator v = new TestProxyPathValidator();
        v.validate(chain, new TrustedCertificates(trustedCerts));
        assertEquals(expectedLimited, v.isLimited());
        assertEquals(expectedIdentity, v.getIdentityCertificate());
    }

    private void validateError(X509Certificate[] chain, X509Certificate[] trustedCerts, int expectedErrorCode) throws Exception {
        TestProxyPathValidator v = new TestProxyPathValidator();
        try {
            v.validate(chain);
            fail("Did not throw exception as expected");
        } catch (ProxyPathValidatorException e) {
            // COMMENT ignore error codes, because new code works with strings
            //assertEquals(expectedErrorCode, e.getErrorCode());
        }
    }

    // for testing only to disable validity checking
    class TestProxyPathValidator extends ProxyPathValidator {

        boolean policyChk = false;
        MockProxyCertPathValidator validator;

        TestProxyPathValidator() {
            super();
            policyChk = false;
            validator = new MockProxyCertPathValidator(false, false, false);
        }

        TestProxyPathValidator(boolean checkSigningPolicy) {
            policyChk = checkSigningPolicy;
            validator = new MockProxyCertPathValidator(false, false, true);
        }

        public void validate(X509Certificate[] certPath) throws ProxyPathValidatorException {
            super.setValidator(validator);
            super.validate(certPath);
        }

        public void validate(X509Certificate[] certPath, TrustedCertificates trustedCerts)
            throws ProxyPathValidatorException {
            super.setValidator(validator);
            super.validate(certPath, trustedCerts);
        }

        public void validate(X509Certificate[] certPath, TrustedCertificates trustedCerts,
            CertificateRevocationLists crlsList, Boolean enforceSigningPolicy) throws ProxyPathValidatorException {
            super.setValidator(validator);
            super.validate(certPath, trustedCerts, crlsList, enforceSigningPolicy);
        }
    }

    // for testing only to disable validity checking

    public class MockProxyCertPathValidator extends X509ProxyCertPathValidator {

        boolean checkCertificateDateValidity;
        boolean checkCRLDateValidity;
        boolean checkSigningPolicy;
        private CertificateChecker dateChecker = new DateValidityChecker();

        public MockProxyCertPathValidator(boolean checkCertificateDateValidity_,
                                          boolean checkCRLDateValidity_,
                                          boolean checkSigningPolicy_) {

            this.checkCertificateDateValidity = checkCertificateDateValidity_;
            this.checkCRLDateValidity = checkCRLDateValidity_;
            this.checkSigningPolicy = checkSigningPolicy_;
        }

        @Override
        protected List<CertificateChecker> getCertificateCheckers() {
            List<CertificateChecker> checkers = new ArrayList<CertificateChecker>();
            if (checkCertificateDateValidity) {
                checkers.add(dateChecker);
            }
            checkers.add(new UnsupportedCriticalExtensionChecker());
            checkers.add(new IdentityChecker(this));
            checkers.add(new CRLChecker(this.certStore, this.keyStore, this.checkCertificateDateValidity));
            if (this.checkSigningPolicy) {
                checkers.add(new SigningPolicyChecker(this.policyStore));
            }
            return checkers;
        }
    }


}
