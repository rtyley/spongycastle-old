package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.mail.internet.MimeBodyPart;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.encoders.Base64;

public class SignedDataTest
    extends TestCase
{

    boolean DEBUG = true;

    MimeBodyPart    msg;

    String          signDN;
    KeyPair         signKP;
    X509Certificate signCert;
    
    KeyPair         signGostKP;
    X509Certificate signGostCert;

    String          origDN;
    KeyPair         origKP;
    X509Certificate origCert;
    
    KeyPair         origGostKP;
    X509Certificate origGostCert;

    String          reciDN;
    KeyPair         reciKP;
    X509Certificate reciCert;

    KeyPair         dsaSignKP;
    X509Certificate dsaSignCert;

    KeyPair         dsaOrigKP;
    X509Certificate dsaOrigCert;

    private byte[] disorderedMessage = Base64.decode(
            "SU9fc3RkaW5fdXNlZABfX2xpYmNfc3RhcnRfbWFpbgBnZXRob3N0aWQAX19n"
          + "bW9uX3M=");

        private byte[] disorderedSet = Base64.decode(
            "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"
          + "UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGLAoGBAIOiqxUkzVyqnvthihnl"
          + "tsE5m1Xn5TZKeR/2MQPStc5hJ+V4yptEtIx+Fn5rOoqT5VEVWhcE35wdbPvg"
          + "JyQFn5msmhPQT/6XSGOlrWRoFummXN9lQzAjCj1sgTcmoLCVQ5s5WpCAOXFw"
          + "VWu16qndz3sPItn3jJ0F3Kh3w79NglvPAgUAwAAAATAKBgYrJAMDAQIFAAOB"
          + "gQBpSRdnDb6AcNVaXSmGo6+kVPIBhot1LzJOGaPyDNpGXxd7LV4tMBF1U7gr"
          + "4k1g9BO6YiMWvw9uiTZmn0CfV8+k4fWEuG/nmafRoGIuay2f+ILuT+C0rnp1"
          + "4FgMsEhuVNJJAmb12QV0PZII+UneyhAneZuQQzVUkTcVgYxogxdSOzCCAlUw"
          + "ggHBoAMCAQICBACdekowCgYGKyQDAwECBQAwbzELMAkGA1UEBhMCREUxPTA7"
          + "BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlr"
          + "YXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNlItQ2Eg"
          + "MTpQTjAiGA8yMDAxMDIwMTEzNDcwN1oYDzIwMDUwMzIyMDg1NTUxWjBvMQsw"
          + "CQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1"
          + "ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9zdDEhMAwGBwKCBgEKBxQTATEw"
          + "EQYDVQQDFAo1Ui1DQSAxOlBOMIGhMA0GCSqGSIb3DQEBAQUAA4GPADCBiwKB"
          + "gQCKHkFTJx8GmoqFTxEOxpK9XkC3NZ5dBEKiUv0Ife3QMqeGMoCUnyJxwW0k"
          + "2/53duHxtv2yHSZpFKjrjvE/uGwdOMqBMTjMzkFg19e9JPv061wyADOucOIa"
          + "NAgha/zFt9XUyrHF21knKCvDNExv2MYIAagkTKajLMAw0bu1J0FadQIFAMAA"
          + "AAEwCgYGKyQDAwECBQADgYEAV1yTi+2gyB7sUhn4PXmi/tmBxAfe5oBjDW8m"
          + "gxtfudxKGZ6l/FUPNcrSc5oqBYxKWtLmf3XX87LcblYsch617jtNTkMzhx9e"
          + "qxiD02ufcrxz2EVt0Akdqiz8mdVeqp3oLcNU/IttpSrcA91CAnoUXtDZYwb/"
          + "gdQ4FI9l3+qo/0UwggJVMIIBwaADAgECAgQAxIymMAoGBiskAwMBAgUAMG8x"
          + "CzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBm"
          + "yHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMB"
          + "MTARBgNVBAMUCjZSLUNhIDE6UE4wIhgPMjAwMTEwMTUxMzMxNThaGA8yMDA1"
          + "MDYwMTA5NTIxN1owbzELMAkGA1UEBhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVy"
          + "dW5nc2JlaMhvcmRlIGbIdXIgVGVsZWtvbW11bmlrYXRpb24gdW5kIFBvc3Qx"
          + "ITAMBgcCggYBCgcUEwExMBEGA1UEAxQKN1ItQ0EgMTpQTjCBoTANBgkqhkiG"
          + "9w0BAQEFAAOBjwAwgYsCgYEAiokD/j6lEP4FexF356OpU5teUpGGfUKjIrFX"
          + "BHc79G0TUzgVxqMoN1PWnWktQvKo8ETaugxLkP9/zfX3aAQzDW4Zki6x6GDq"
          + "fy09Agk+RJvhfbbIzRkV4sBBco0n73x7TfG/9NTgVr/96U+I+z/1j30aboM6"
          + "9OkLEhjxAr0/GbsCBQDAAAABMAoGBiskAwMBAgUAA4GBAHWRqRixt+EuqHhR"
          + "K1kIxKGZL2vZuakYV0R24Gv/0ZR52FE4ECr+I49o8FP1qiGSwnXB0SwjuH2S"
          + "iGiSJi+iH/MeY85IHwW1P5e+bOMvEOFhZhQXQixOD7totIoFtdyaj1XGYRef"
          + "0f2cPOjNJorXHGV8wuBk+/j++sxbd/Net3FtMIICVTCCAcGgAwIBAgIEAMSM"
          + "pzAKBgYrJAMDAQIFADBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxp"
          + "ZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9z"
          + "dDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAo3Ui1DQSAxOlBOMCIYDzIwMDEx"
          + "MDE1MTMzNDE0WhgPMjAwNTA2MDEwOTUyMTdaMG8xCzAJBgNVBAYTAkRFMT0w"
          + "OwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBmyHVyIFRlbGVrb21tdW5p"
          + "a2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMBMTARBgNVBAMUCjZSLUNh"
          + "IDE6UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGLAoGBAIOiqxUkzVyqnvth"
          + "ihnltsE5m1Xn5TZKeR/2MQPStc5hJ+V4yptEtIx+Fn5rOoqT5VEVWhcE35wd"
          + "bPvgJyQFn5msmhPQT/6XSGOlrWRoFummXN9lQzAjCj1sgTcmoLCVQ5s5WpCA"
          + "OXFwVWu16qndz3sPItn3jJ0F3Kh3w79NglvPAgUAwAAAATAKBgYrJAMDAQIF"
          + "AAOBgQBi5W96UVDoNIRkCncqr1LLG9vF9SGBIkvFpLDIIbcvp+CXhlvsdCJl"
          + "0pt2QEPSDl4cmpOet+CxJTdTuMeBNXxhb7Dvualog69w/+K2JbPhZYxuVFZs"
          + "Zh5BkPn2FnbNu3YbJhE60aIkikr72J4XZsI5DxpZCGh6xyV/YPRdKSljFjCC"
          + "AlQwggHAoAMCAQICAwyDqzAKBgYrJAMDAQIFADBvMQswCQYDVQQGEwJERTE9"
          + "MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVu"
          + "aWthdGlvbiB1bmQgUG9zdDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAo1Ui1D"
          + "QSAxOlBOMCIYDzIwMDAwMzIyMDk0MTI3WhgPMjAwNDAxMjExNjA0NTNaMG8x"
          + "CzAJBgNVBAYTAkRFMT0wOwYDVQQKFDRSZWd1bGllcnVuZ3NiZWjIb3JkZSBm"
          + "yHVyIFRlbGVrb21tdW5pa2F0aW9uIHVuZCBQb3N0MSEwDAYHAoIGAQoHFBMB"
          + "MTARBgNVBAMUCjRSLUNBIDE6UE4wgaEwDQYJKoZIhvcNAQEBBQADgY8AMIGL"
          + "AoGBAI8x26tmrFJanlm100B7KGlRemCD1R93PwdnG7svRyf5ZxOsdGrDszNg"
          + "xg6ouO8ZHQMT3NC2dH8TvO65Js+8bIyTm51azF6clEg0qeWNMKiiXbBXa+ph"
          + "hTkGbXiLYvACZ6/MTJMJ1lcrjpRF7BXtYeYMcEF6znD4pxOqrtbf9z5hAgUA"
          + "wAAAATAKBgYrJAMDAQIFAAOBgQB99BjSKlGPbMLQAgXlvA9jUsDNhpnVm3a1"
          + "YkfxSqS/dbQlYkbOKvCxkPGA9NBxisBM8l1zFynVjJoy++aysRmcnLY/sHaz"
          + "23BF2iU7WERy18H3lMBfYB6sXkfYiZtvQZcWaO48m73ZBySuiV3iXpb2wgs/"
          + "Cs20iqroAWxwq/W/9jCCAlMwggG/oAMCAQICBDsFZ9UwCgYGKyQDAwECBQAw"
          + "bzELMAkGA1UEBhMCREUxITAMBgcCggYBCgcUEwExMBEGA1UEAxQKNFItQ0Eg"
          + "MTpQTjE9MDsGA1UEChQ0UmVndWxpZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxl"
          + "a29tbXVuaWthdGlvbiB1bmQgUG9zdDAiGA8xOTk5MDEyMTE3MzUzNFoYDzIw"
          + "MDQwMTIxMTYwMDAyWjBvMQswCQYDVQQGEwJERTE9MDsGA1UEChQ0UmVndWxp"
          + "ZXJ1bmdzYmVoyG9yZGUgZsh1ciBUZWxla29tbXVuaWthdGlvbiB1bmQgUG9z"
          + "dDEhMAwGBwKCBgEKBxQTATEwEQYDVQQDFAozUi1DQSAxOlBOMIGfMA0GCSqG"
          + "SIb3DQEBAQUAA4GNADCBiQKBgI4B557mbKQg/AqWBXNJhaT/6lwV93HUl4U8"
          + "u35udLq2+u9phns1WZkdM3gDfEpL002PeLfHr1ID/96dDYf04lAXQfombils"
          + "of1C1k32xOvxjlcrDOuPEMxz9/HDAQZA5MjmmYHAIulGI8Qg4Tc7ERRtg/hd"
          + "0QX0/zoOeXoDSEOBAgTAAAABMAoGBiskAwMBAgUAA4GBAIyzwfT3keHI/n2P"
          + "LrarRJv96mCohmDZNpUQdZTVjGu5VQjVJwk3hpagU0o/t/FkdzAjOdfEw8Ql"
          + "3WXhfIbNLv1YafMm2eWSdeYbLcbB5yJ1od+SYyf9+tm7cwfDAcr22jNRBqx8"
          + "wkWKtKDjWKkevaSdy99sAI8jebHtWz7jzydKMIID9TCCA16gAwIBAgICbMcw"
          + "DQYJKoZIhvcNAQEFBQAwSzELMAkGA1UEBhMCREUxEjAQBgNVBAoUCVNpZ250"
          + "cnVzdDEoMAwGBwKCBgEKBxQTATEwGAYDVQQDFBFDQSBTSUdOVFJVU1QgMTpQ"
          + "TjAeFw0wNDA3MzAxMzAyNDZaFw0wNzA3MzAxMzAyNDZaMDwxETAPBgNVBAMM"
          + "CFlhY29tOlBOMQ4wDAYDVQRBDAVZYWNvbTELMAkGA1UEBhMCREUxCjAIBgNV"
          + "BAUTATEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAIWzLlYLQApocXIp"
          + "pgCCpkkOUVLgcLYKeOd6/bXAnI2dTHQqT2bv7qzfUnYvOqiNgYdF13pOYtKg"
          + "XwXMTNFL4ZOI6GoBdNs9TQiZ7KEWnqnr2945HYx7UpgTBclbOK/wGHuCdcwO"
          + "x7juZs1ZQPFG0Lv8RoiV9s6HP7POqh1sO0P/AgMBAAGjggH1MIIB8TCBnAYD"
          + "VR0jBIGUMIGRgBQcZzNghfnXoXRm8h1+VITC5caNRqFzpHEwbzELMAkGA1UE"
          + "BhMCREUxPTA7BgNVBAoUNFJlZ3VsaWVydW5nc2JlaMhvcmRlIGbIdXIgVGVs"
          + "ZWtvbW11bmlrYXRpb24gdW5kIFBvc3QxITAMBgcCggYBCgcUEwExMBEGA1UE"
          + "AxQKNVItQ0EgMTpQToIEALs8rjAdBgNVHQ4EFgQU2e5KAzkVuKaM9I5heXkz"
          + "bcAIuR8wDgYDVR0PAQH/BAQDAgZAMBIGA1UdIAQLMAkwBwYFKyQIAQEwfwYD"
          + "VR0fBHgwdjB0oCygKoYobGRhcDovL2Rpci5zaWdudHJ1c3QuZGUvbz1TaWdu"
          + "dHJ1c3QsYz1kZaJEpEIwQDEdMBsGA1UEAxMUQ1JMU2lnblNpZ250cnVzdDE6"
          + "UE4xEjAQBgNVBAoTCVNpZ250cnVzdDELMAkGA1UEBhMCREUwYgYIKwYBBQUH"
          + "AQEEVjBUMFIGCCsGAQUFBzABhkZodHRwOi8vZGlyLnNpZ250cnVzdC5kZS9T"
          + "aWdudHJ1c3QvT0NTUC9zZXJ2bGV0L2h0dHBHYXRld2F5LlBvc3RIYW5kbGVy"
          + "MBgGCCsGAQUFBwEDBAwwCjAIBgYEAI5GAQEwDgYHAoIGAQoMAAQDAQH/MA0G"
          + "CSqGSIb3DQEBBQUAA4GBAHn1m3GcoyD5GBkKUY/OdtD6Sj38LYqYCF+qDbJR"
          + "6pqUBjY2wsvXepUppEler+stH8mwpDDSJXrJyuzf7xroDs4dkLl+Rs2x+2tg"
          + "BjU+ABkBDMsym2WpwgA8LCdymmXmjdv9tULxY+ec2pjSEzql6nEZNEfrU8nt"
          + "ZCSCavgqW4TtMYIBejCCAXYCAQEwUTBLMQswCQYDVQQGEwJERTESMBAGA1UE"
          + "ChQJU2lnbnRydXN0MSgwDAYHAoIGAQoHFBMBMTAYBgNVBAMUEUNBIFNJR05U"
          + "UlVTVCAxOlBOAgJsxzAJBgUrDgMCGgUAoIGAMBgGCSqGSIb3DQEJAzELBgkq"
          + "hkiG9w0BBwEwIwYJKoZIhvcNAQkEMRYEFIYfhPoyfGzkLWWSSLjaHb4HQmaK"
          + "MBwGCSqGSIb3DQEJBTEPFw0wNTAzMjQwNzM4MzVaMCEGBSskCAYFMRgWFi92"
          + "YXIvZmlsZXMvdG1wXzEvdGVzdDEwDQYJKoZIhvcNAQEFBQAEgYA2IvA8lhVz"
          + "VD5e/itUxbFboKxeKnqJ5n/KuO/uBCl1N14+7Z2vtw1sfkIG+bJdp3OY2Cmn"
          + "mrQcwsN99Vjal4cXVj8t+DJzFG9tK9dSLvD3q9zT/GQ0kJXfimLVwCa4NaSf"
          + "Qsu4xtG0Rav6bCcnzabAkKuNNvKtH8amSRzk870DBg==");

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public SignedDataTest(String name) {
        super(name);
    }

    public static void main(String args[]) {

        junit.textui.TestRunner.run(SignedDataTest.class);
    }

    public static Test suite() {
        return new TestSuite(SignedDataTest.class);
    }

    public void log(Exception _ex) {
        if(DEBUG) {
            _ex.printStackTrace();
        }
    }

    public void log(String _msg) {
        if(DEBUG) {
            System.out.println(_msg);
        }
    }

    public void setUp()
    {
        try
        {
            signDN   = "O=Bouncy Castle, C=AU";
            signKP   = CMSTestUtil.makeKeyPair();  
            signCert = CMSTestUtil.makeCertificate(signKP, signDN, signKP, signDN);

            signGostKP   = CMSTestUtil.makeGostKeyPair();  
            signGostCert = CMSTestUtil.makeCertificate(signGostKP, signDN, signGostKP, signDN);
            
            origDN   = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
            origKP   = CMSTestUtil.makeKeyPair();
            origCert = CMSTestUtil.makeCertificate(origKP, origDN, signKP, signDN);
            
            origGostKP   = CMSTestUtil.makeGostKeyPair();
            origGostCert = CMSTestUtil.makeCertificate(origGostKP, origDN, signGostKP, signDN);
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }

    public void tearDown() {

    }

    /*
     *
     *  TESTS
     *
     */

    public void testSHA1AndMD5WithRSAEncapsulatedRepeated()
    {
        try
        {
            ArrayList           certList = new ArrayList();
            CMSProcessable      msg = new CMSProcessableByteArray("Hello World!".getBytes());

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, CMSSignedDataGenerator.DIGEST_SHA1);

            gen.addSigner(origKP.getPrivate(), origCert, CMSSignedDataGenerator.DIGEST_MD5);
            
            gen.addCertificatesAndCRLs(certs);

            CMSSignedData s = gen.generate(msg, true, "BC");

            ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
            ASN1InputStream      aIn = new ASN1InputStream(bIn);
            
            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = s.getSignerInfos();
            
            assertEquals(2, signers.size());
            
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();
            SignerId                sid = null;

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                sid = signer.getSID();
                
                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            c = signers.getSigners(sid);
            
            assertEquals(2, c.size());
            
            //
            // try using existing signer
            //
            
            gen = new CMSSignedDataGenerator();
               
            gen.addSigners(s.getSignerInfos());
            
            gen.addCertificatesAndCRLs(s.getCertificatesAndCRLs("Collection", "BC"));
               
            s = gen.generate(msg, true, "BC");

            bIn = new ByteArrayInputStream(s.getEncoded());
            aIn = new ASN1InputStream(bIn);

            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // signerInformation store replacement test.
            //
            s = CMSSignedData.replaceSigners(s, signers);
            
            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }

    public void testSHA1WithRSAEncapsulated()
    {
        try
        {
            ArrayList           certList = new ArrayList();
            CMSProcessable      msg = new CMSProcessableByteArray("Hello World!".getBytes());

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, CMSSignedDataGenerator.DIGEST_SHA1);

            gen.addCertificatesAndCRLs(certs);

            CMSSignedData s = gen.generate(msg, true, "BC");

            ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
            ASN1InputStream      aIn = new ASN1InputStream(bIn);
            
            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = s.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // try using existing signer
            //
            
            gen = new CMSSignedDataGenerator();
               
            gen.addSigners(s.getSignerInfos());
            
            gen.addCertificatesAndCRLs(s.getCertificatesAndCRLs("Collection", "BC"));
               
            s = gen.generate(msg, true, "BC");

            bIn = new ByteArrayInputStream(s.getEncoded());
            aIn = new ASN1InputStream(bIn);

            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // signerInformation store replacement test.
            //
            s = CMSSignedData.replaceSigners(s, signers);
            
            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
    
    public void testSHA224WithRSAEncapsulated()
    {
        try
        {
            ArrayList           certList = new ArrayList();
            CMSProcessable      msg = new CMSProcessableByteArray("Hello World!".getBytes());

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, CMSSignedDataGenerator.DIGEST_SHA224);

            gen.addCertificatesAndCRLs(certs);

            CMSSignedData s = gen.generate(msg, true, "BC");

            ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
            ASN1InputStream      aIn = new ASN1InputStream(bIn);
            
            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = s.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // try using existing signer
            //
            
            gen = new CMSSignedDataGenerator();
               
            gen.addSigners(s.getSignerInfos());
            
            gen.addCertificatesAndCRLs(s.getCertificatesAndCRLs("Collection", "BC"));
               
            s = gen.generate(msg, true, "BC");

            bIn = new ByteArrayInputStream(s.getEncoded());
            aIn = new ASN1InputStream(bIn);

            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // signerInformation store replacement test.
            //
            s = CMSSignedData.replaceSigners(s, signers);
            
            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
    
    public void testSHA256WithRSAEncapsulated()
    {
        try
        {
            ArrayList           certList = new ArrayList();
            CMSProcessable      msg = new CMSProcessableByteArray("Hello World!".getBytes());

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, CMSSignedDataGenerator.DIGEST_SHA256);

            gen.addCertificatesAndCRLs(certs);

            CMSSignedData s = gen.generate(msg, true, "BC");

            ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
            ASN1InputStream      aIn = new ASN1InputStream(bIn);
            
            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = s.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // try using existing signer
            //
            
            gen = new CMSSignedDataGenerator();
               
            gen.addSigners(s.getSignerInfos());
            
            gen.addCertificatesAndCRLs(s.getCertificatesAndCRLs("Collection", "BC"));
               
            s = gen.generate(msg, true, "BC");

            bIn = new ByteArrayInputStream(s.getEncoded());
            aIn = new ASN1InputStream(bIn);

            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // signerInformation store replacement test.
            //
            s = CMSSignedData.replaceSigners(s, signers);
            
            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
    
    public void testGOST3411WithGOST3410Encapsulated()
    {
        try
        {
            ArrayList           certList = new ArrayList();
            CMSProcessable      msg = new CMSProcessableByteArray("Hello World!".getBytes());

            certList.add(origGostCert);
            certList.add(signGostCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

            gen.addSigner(origGostKP.getPrivate(), origGostCert, CMSSignedDataGenerator.DIGEST_GOST3411);

            gen.addCertificatesAndCRLs(certs);

            CMSSignedData s = gen.generate(msg, true, "BC");

            ByteArrayInputStream bIn = new ByteArrayInputStream(s.getEncoded());
            ASN1InputStream      aIn = new ASN1InputStream(bIn);
            
            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = s.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // try using existing signer
            //
            
            gen = new CMSSignedDataGenerator();
               
            gen.addSigners(s.getSignerInfos());
            
            gen.addCertificatesAndCRLs(s.getCertificatesAndCRLs("Collection", "BC"));
               
            s = gen.generate(msg, true, "BC");

            bIn = new ByteArrayInputStream(s.getEncoded());
            aIn = new ASN1InputStream(bIn);

            s = new CMSSignedData(ContentInfo.getInstance(aIn.readObject()));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
            
            //
            // signerInformation store replacement test.
            //
            s = CMSSignedData.replaceSigners(s, signers);
            
            signers = s.getSignerInfos();
            c = signers.getSigners();
            it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
    
    public void testUnsortedAttributes()
    {
        try
        {
            CMSSignedData s = new CMSSignedData(new CMSProcessableByteArray(disorderedMessage), disorderedSet);

            CertStore certs = s.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = s.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator        certIt = certCollection.iterator();
                X509Certificate cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
}
