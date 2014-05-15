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
package org.globus.gsi.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import org.globus.gsi.testutils.FileSetupUtil;
import org.globus.gsi.util.CertificateLoadUtil;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;

/**
 * FILL ME
 *
 * @author ranantha@mcs.anl.gov
 */
public class CertificateUtilTest {

    String validCert1 =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIID+DCCAuCgAwIBAgIBKTANBgkqhkiG9w0BAQUFADB1MRMwEQYKCZImiZPyLGQB\n" +
                    "GRYDbmV0MRIwEAYKCZImiZPyLGQBGRYCRVMxDjAMBgNVBAoTBUVTbmV0MSAwHgYD\n" +
                    "VQQLExdDZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEYMBYGA1UEAxMPRVNuZXQgUm9v\n" +
                    "dCBDQSAxMB4XDTAyMTIwNTA4MDAwMFoXDTEzMDEyNTA4MDAwMFowaTETMBEGCgmS\n" +
                    "JomT8ixkARkWA29yZzEYMBYGCgmSJomT8ixkARkWCERPRUdyaWRzMSAwHgYDVQQL\n" +
                    "ExdDZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEWMBQGA1UEAxMNRE9FR3JpZHMgQ0Eg\n" +
                    "MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALT11iNho9sIPma1uJBv\n" +
                    "sprfLWoCbRlyooIVyJZx97wrBy7L22Me4iwt/1ki12QNbjHLyy5r2cmXHcqXCO26\n" +
                    "ZMy062DfkpkKSdR3wozhUZNIV0tUb0Bs1rJ5/vpxpUIYzX6PIXQurTeRq4Y49Nw1\n" +
                    "9l7VNlrd7Vz2tzyWNXk5JZr+Z+wIALJLnMUha7TIgM3Il1/6fSHBo83nfCWWknfS\n" +
                    "1oP4kGNDuHaTjFFbN5rOcs5v07O1lVED/WxXN76JzMWHbHBrhV0bLR4gg/DWl+9j\n" +
                    "DE7fqubRLXT2q9uw2Vqug9FvF6s8pqRAukp7TfhdzHuAE+pST8XGhFFaKfkRY3ev\n" +
                    "P0sCAwEAAaOBnjCBmzAOBgNVHQ8BAf8EBAMCAYYwEQYJYIZIAYb4QgEBBAQDAgCH\n" +
                    "MB0GA1UdDgQWBBTKGR0Sjm6kOF1C1DEOCNvZjRcNXTAfBgNVHSMEGDAWgBS8XU1I\n" +
                    "L/g1lFmrXIlLPtGyOhQB6jAPBgNVHRMBAf8EBTADAQH/MCUGA1UdEQQeMByBGkRP\n" +
                    "RUdyaWRzLUNBLTFAZG9lZ3JpZHMub3JnMA0GCSqGSIb3DQEBBQUAA4IBAQBk1Wsg\n" +
                    "Mup7f0IQ6Im3tDsSkE+ECKEy8NNJ//ja7RIxtSYKHDDiYuamHkMGCFlRUXxifn2R\n" +
                    "FkyfVAs607UfMuq8C88hNpxlU+UmAbYhfOVHrfpiCFkUDJxshQQ4kMEdHi+1A7Uo\n" +
                    "PGBnC8Bu2YoijG+FQKrbGx8W32QIEGf4li1Do7kuwEmrc+a65t4xxzuZtAB8lnuH\n" +
                    "/dCCGCQUiGYTX4sFc8luS4/y+B+DqHYEqgB/lMV9kQKAZkqKZ83XXS0G9950ZnBh\n" +
                    "h3f8awlzzcHQk3WCfLSCo1U+bf3ZRyFcZ4FGseebaCSEiSvjw6roSY0ZX39rpd9u\n" +
                    "mVBb8lZu09U9aRqL\n" +
                    "-----END CERTIFICATE-----";

    String invalidCert1 =
            "MB0GA1UdDgQWBBTKGR0Sjm6kOF1C1DEOCNvZjRcNXTAfBgNVHSMEGDAWgBS8XU1I\n" +
                    "L/g1lFmrXIlLPtGyOhQB6jAPBgNVHRMBAf8EBTADAQH/MCUGA1UdEQQeMByBGkRP\n" +
                    "RUdyaWRzLUNBLTFAZG9lZ3JpZHMub3JnMA0GCSqGSIb3DQEBBQUAA4IBAQBk1Wsg\n" +
                    "Mup7f0IQ6Im3tDsSkE+ECKEy8NNJ//ja7RIxtSYKHDDiYuamHkMGCFlRUXxifn2R\n" +
                    "FkyfVAs607UfMuq8C88hNpxlU+UmAbYhfOVHrfpiCFkUDJxshQQ4kMEdHi+1A7Uo\n" +
                    "PGBnC8Bu2YoijG+FQKrbGx8W32QIEGf4li1Do7kuwEmrc+a65t4xxzuZtAB8lnuH\n" +
                    "/dCCGCQUiGYTX4sFc8luS4/y+B+DqHYEqgB/lMV9kQKAZkqKZ83XXS0G9950ZnBh\n" +
                    "h3f8awlzzcHQk3WCfLSCo1U+bf3ZRyFcZ4FGseebaCSEiSvjw6roSY0ZX39rpd9u\n" +
                    "mVBb8lZu09U9aRqL\n" +
                    "-----END CERTIFICATE-----";

    String invalidCert2 =
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIID+DCCAuCgAwIBAgIBKTANBgkqhkiG9w0BAQUFADB1MRMwEQYKCZImiZPyLGQB\n" +
                    "GRYDbmV0MRIwEAYKCZImiZPyLGQBGRYCRVMxDjAMBgNVBAoTBUVTbmV0MSAwHgYD\n" +
                    "VQQLExdDZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEYMBYGA1UEAxMPRVNuZXQgUm9v\n" +
                    "dCBDQSAxMB4XDTAyMTIwNTA4MDAwMFoXDTEzMDEyNTA4MDAwMFowaTETMBEGCgmS\n" +
                    "JomT8ixkARkWA29yZzEYMBYGCgmSJomT8ixkARkWCERPRUdyaWRzMSAwHgYDVQQL\n" +
                    "ExdDZXJ0aWZpY2F0ZSBBdXRob3JpdGllczEWMBQGA1UEAxMNRE9FR3JpZHMgQ0Eg\n" +
                    "MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALT11iNho9sIPma1uJBv\n" +
                    "sprfLWoCbRlyooIVyJZx97wrBy7L22Me4iwt/1ki12QNbjHLyy5r2cmXHcqXCO26\n" +
                    "ZMy062DfkpkKSdR3wozhUZNIV0tUb0Bs1rJ5/vpxpUIYzX6PIXQurTeRq4Y49Nw1\n";

    String invalidCrl1 =
            "-----BEGIN X509 CRL-----\n" +
                    "MIIBLDCBljANBgkqhkiG9w0BAQQFADA9MREwDwYDVQQKEwh0ZXN0IENBMjESMBAG\n" +
                    "A1UECxMJc2ltcGxlIGNhMRQwEgYDVQQDEwtHbG9idXMgVGVzdBcNMDYwNTIzMDEy\n" +
                    "NjEwWhcNMDcwNTIzMDEyNjEwWjAoMBICAQIXDTA2MDUyMzAxMTM1MFowEgIBAxcN";

    FileSetupUtil testCert1;
    FileSetupUtil testCert2;
    FileSetupUtil testCrl1;

    @Before
    public void setup() throws Exception {

        this.testCert1 = new FileSetupUtil("certificateUtilTest/1c3f2ca8.0");

        this.testCert2 =
                new FileSetupUtil("certificateUtilTest/b38b4d8c-invalid.0");

        this.testCrl1 = new FileSetupUtil("certificateUtilTest/validCrl.r0");
    }

    @Test
    public void testReadCertificate() throws Exception {

        BufferedReader reader =
                new BufferedReader(new StringReader(this.validCert1));
        X509Certificate cert =
                CertificateLoadUtil.readCertificate(reader);
        assert (cert != null);

        reader = new BufferedReader(new StringReader(this.invalidCert1));

        boolean expected = false;
        try {
            cert = CertificateLoadUtil.readCertificate(reader);
        } catch (GeneralSecurityException e) {

            if ((e.getMessage().indexOf(
                    "Certificate needs to start with  BEGIN CERTIFICATE")) != -1) {
                expected = true;
            }
        }
        assertTrue(expected);

        reader = new BufferedReader(new StringReader(this.invalidCert1));

        expected = false;
        try {
            cert = CertificateLoadUtil.readCertificate(reader);
        } catch (GeneralSecurityException e) {

            if ((e.getMessage().indexOf(
                    "Certificate needs to start with  BEGIN CERTIFICATE")) != -1) {
                expected = true;
            }
        }
        assertTrue(expected);
    }

    @Test
    public void testLoadCertificate() throws Exception {
        {

            this.testCert1.copyFileToTemp();

            X509Certificate cert =
                    CertificateLoadUtil
                            .loadCertificate(testCert1.getAbsoluteFilename());

            assert (cert != null);

            this.testCert2.copyFileToTemp();

            boolean worked = false;
            try {
                cert = CertificateLoadUtil
                        .loadCertificate(testCert2.getAbsoluteFilename());
            } catch (GeneralSecurityException e) {
                String err = e.getMessage();
                if (err != null &&
                        err.indexOf("BEGIN CERTIFICATE") != -1) {
                    worked = true;
                }
            }

            assertTrue(worked);
        }
    }

    @Test
    public void testLoadCrl() throws Exception {

        this.testCrl1.copyFileToTemp();

        X509CRL crl =
                CertificateLoadUtil.loadCrl(testCrl1.getAbsoluteFilename());

        assert (crl != null);

        ByteArrayInputStream in =
                new ByteArrayInputStream(this.invalidCrl1.getBytes());

        boolean worked = false;
        try {
            crl = CertificateLoadUtil.loadCrl(in);
        } catch (GeneralSecurityException e) {
            worked = true;
        }

        assertTrue(worked);
    }

    @Test
    public void testToGlobusIdForString()
    {
        String dn =
            CertificateUtil.toGlobusID("DC=org, DC=DOEGrids, OU=Certificate Authorities, CN=DOEGrids CA 1",  true);
        assertThat(dn, is("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"));
    }

    @Test
    public void testToGlobusIdForReverseString()
    {
        String dn =
            CertificateUtil.toGlobusID("CN=DOEGrids CA 1, OU=Certificate Authorities, DC=DOEGrids, DC=org",  false);
        assertThat(dn, is("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"));
    }

    @Test
    public void testToGlobusIdForX500Principal()
    {
        String dn = CertificateUtil.toGlobusID(
            new X500Principal("CN=DOEGrids CA 1, OU=Certificate Authorities, DC=DOEGrids, DC=org"));
        assertThat(dn, is("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1"));
    }

    @Test
    public void testToPrincipal()
    {
        X500Principal principal =
            CertificateUtil.toPrincipal("/DC=org/DC=DOEGrids/OU=Certificate Authorities/CN=DOEGrids CA 1");
        assertThat(principal, is(new X500Principal(
            "CN=DOEGrids CA 1, OU=Certificate Authorities, DC=DOEGrids, DC=org")));
    }

    @Test
    public void testToPrincipalWithSlashInAttribute()
    {
        X500Principal principal =
            CertificateUtil.toPrincipal("/DC=org/DC=DOEGrids/OU=Certificate / Authorities/CN=DOEGrids CA 1");
        assertThat(principal, is(new X500Principal(
            "CN=DOEGrids CA 1, OU=Certificate / Authorities, DC=DOEGrids, DC=org")));
    }

    @Test
    public void testToPrincipalWithEmptyAttribute()
    {
        X500Principal principal =
            CertificateUtil.toPrincipal("/DC=org/DC=DOEGrids//CN=DOEGrids CA 1");
        assertThat(principal, is(new X500Principal(
            "CN=DOEGrids CA 1, DC=DOEGrids, DC=org")));
    }

    @Test
    public void testToPrincipalWithEmptyString()
    {
        X500Principal principal =
            CertificateUtil.toPrincipal("");
        assertThat(principal, is(new X500Principal("")));
    }

    @Test
    public void testToPrincipalWithWhiteSpace()
    {
        X500Principal principal =
            CertificateUtil.toPrincipal(" /DC=org/ DC=DOEGrids/OU=Certificate Authorities / CN=DOEGrids CA 1   ");
        assertThat(principal, is(new X500Principal(
            "CN=DOEGrids CA 1, OU=Certificate Authorities, DC=DOEGrids, DC=org")));
    }

    @Test
    public void testToPrincipalWithRdnUnknownToJre()
    {
        String dn = "/DC=org/DC=terena/DC=tcs/C=FI/PostalCode=02101/ST=Uusimaa/L=Espoo/STREET=P.O. Box " +
            "405/O=CSC/OU=satellite.csc.fi/CN=liuske.csc.fi";
        X500Principal principal = CertificateUtil.toPrincipal(dn);
        String newDn = CertificateUtil.toGlobusID(principal);
        assertThat(newDn, is(dn));
    }

    @Test
    public void testToPrincipalWithUrl() {
        String dn = "/C=US/ST=UT/L=Salt Lake City/O=The USERTRUST Network"
                + "/OU=http://www.usertrust.com/CN=UTN-USERFirst-Client Authentication and Email";
        X500Principal principal = CertificateUtil.toPrincipal(dn);
        String newDn = CertificateUtil.toGlobusID(principal);
        assertThat(newDn, is(dn));
    }

    @Test
    public void testToPrincipalWithComma() {
        String dn = "/C=DE/ST=Hamburg/O=dCache.ORG/CN=Gena, Crocodile";
        X500Principal principal = CertificateUtil.toPrincipal(dn);
        String newDn = CertificateUtil.toGlobusID(principal);
        assertThat(newDn, is(dn));
    }

    @After
    public void tearDown() {

        this.testCert1.deleteFile();
        this.testCert2.deleteFile();
        this.testCrl1.deleteFile();
    }
}
