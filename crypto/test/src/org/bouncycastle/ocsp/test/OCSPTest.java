package org.bouncycastle.ocsp.test;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespGenerator;
import org.bouncycastle.ocsp.Req;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;
import java.util.Set;
import java.util.Vector;

public class OCSPTest
    extends SimpleTest
{
    byte[]  testResp1 = Base64.decode(
                "MIIFnAoBAKCCBZUwggWRBgkrBgEFBQcwAQEEggWCMIIFfjCCARehgZ8wgZwx"
              + "CzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEgcHJhZGVzaDESMBAGA1UE"
              + "BxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAKBgNVBAsTA0FUQzEeMBwG"
              + "A1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQwIgYJKoZIhvcNAQkBFhVv"
              + "Y3NwQHRjcy1jYS50Y3MuY28uaW4YDzIwMDMwNDAyMTIzNDU4WjBiMGAwOjAJ"
              + "BgUrDgMCGgUABBRs07IuoCWNmcEl1oHwIak1BPnX8QQUtGyl/iL9WJ1VxjxF"
              + "j0hAwJ/s1AcCAQKhERgPMjAwMjA4MjkwNzA5MjZaGA8yMDAzMDQwMjEyMzQ1"
              + "OFowDQYJKoZIhvcNAQEFBQADgYEAfbN0TCRFKdhsmvOdUoiJ+qvygGBzDxD/"
              + "VWhXYA+16AphHLIWNABR3CgHB3zWtdy2j7DJmQ/R7qKj7dUhWLSqclAiPgFt"
              + "QQ1YvSJAYfEIdyHkxv4NP0LSogxrumANcDyC9yt/W9yHjD2ICPBIqCsZLuLk"
              + "OHYi5DlwWe9Zm9VFwCGgggPMMIIDyDCCA8QwggKsoAMCAQICAQYwDQYJKoZI"
              + "hvcNAQEFBQAwgZQxFDASBgNVBAMTC1RDUy1DQSBPQ1NQMSYwJAYJKoZIhvcN"
              + "AQkBFhd0Y3MtY2FAdGNzLWNhLnRjcy5jby5pbjEMMAoGA1UEChMDVENTMQww"
              + "CgYDVQQLEwNBVEMxEjAQBgNVBAcTCUh5ZGVyYWJhZDEXMBUGA1UECBMOQW5k"
              + "aHJhIHByYWRlc2gxCzAJBgNVBAYTAklOMB4XDTAyMDgyOTA3MTE0M1oXDTAz"
              + "MDgyOTA3MTE0M1owgZwxCzAJBgNVBAYTAklOMRcwFQYDVQQIEw5BbmRocmEg"
              + "cHJhZGVzaDESMBAGA1UEBxMJSHlkZXJhYmFkMQwwCgYDVQQKEwNUQ1MxDDAK"
              + "BgNVBAsTA0FUQzEeMBwGA1UEAxMVVENTLUNBIE9DU1AgUmVzcG9uZGVyMSQw"
              + "IgYJKoZIhvcNAQkBFhVvY3NwQHRjcy1jYS50Y3MuY28uaW4wgZ8wDQYJKoZI"
              + "hvcNAQEBBQADgY0AMIGJAoGBAM+XWW4caMRv46D7L6Bv8iwtKgmQu0SAybmF"
              + "RJiz12qXzdvTLt8C75OdgmUomxp0+gW/4XlTPUqOMQWv463aZRv9Ust4f8MH"
              + "EJh4ekP/NS9+d8vEO3P40ntQkmSMcFmtA9E1koUtQ3MSJlcs441JjbgUaVnm"
              + "jDmmniQnZY4bU3tVAgMBAAGjgZowgZcwDAYDVR0TAQH/BAIwADALBgNVHQ8E"
              + "BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwkwNgYIKwYBBQUHAQEEKjAoMCYG"
              + "CCsGAQUFBzABhhpodHRwOi8vMTcyLjE5LjQwLjExMDo3NzAwLzAtBgNVHR8E"
              + "JjAkMCKgIKAehhxodHRwOi8vMTcyLjE5LjQwLjExMC9jcmwuY3JsMA0GCSqG"
              + "SIb3DQEBBQUAA4IBAQB6FovM3B4VDDZ15o12gnADZsIk9fTAczLlcrmXLNN4"
              + "PgmqgnwF0Ymj3bD5SavDOXxbA65AZJ7rBNAguLUo+xVkgxmoBH7R2sBxjTCc"
              + "r07NEadxM3HQkt0aX5XYEl8eRoifwqYAI9h0ziZfTNes8elNfb3DoPPjqq6V"
              + "mMg0f0iMS4W8LjNPorjRB+kIosa1deAGPhq0eJ8yr0/s2QR2/WFD5P4aXc8I"
              + "KWleklnIImS3zqiPrq6tl2Bm8DZj7vXlTOwmraSQxUwzCKwYob1yGvNOUQTq"
              + "pG6jxn7jgDawHU1+WjWQe4Q34/pWeGLysxTraMa+Ug9kPe+jy/qRX2xwvKBZ"
              + "====");

    byte[]  testResp2 = Base64.decode(
                "MIII1QoBAKCCCM4wggjKBgkrBgEFBQcwAQEEggi7MIIItzCBjqADAgEAoSMw"
              + "ITEfMB0GA1UEAxMWT0NTUCBjZXJ0LVFBLUNMSUVOVC04NxgPMjAwMzA1MTky"
              + "MDI2MzBaMFEwTzA6MAkGBSsOAwIaBQAEFJniwiUuyrhKIEF2TjVdVdCAOw0z"
              + "BBR2olPKrPOJUVyGZ7BXOC4L2BmAqgIBL4AAGA8yMDAzMDUxOTIwMjYzMFow"
              + "DQYJKoZIhvcNAQEEBQADggEBALImFU3kUtpNVf4tIFKg/1sDHvGpk5Pk0uhH"
              + "TiNp6vdPfWjOgPkVXskx9nOTabVOBE8RusgwEcK1xeBXSHODb6mnjt9pkfv3"
              + "ZdbFLFvH/PYjOb6zQOgdIOXhquCs5XbcaSFCX63hqnSaEqvc9w9ctmQwds5X"
              + "tCuyCB1fWu/ie8xfuXR5XZKTBf5c6dO82qFE65gTYbGOxJBYiRieIPW1XutZ"
              + "A76qla4m+WdxubV6SPG8PVbzmAseqjsJRn4jkSKOGenqSOqbPbZn9oBsU0Ku"
              + "hul3pwsNJvcBvw2qxnWybqSzV+n4OvYXk+xFmtTjw8H9ChV3FYYDs8NuUAKf"
              + "jw1IjWegggcOMIIHCjCCAzMwggIboAMCAQICAQIwDQYJKoZIhvcNAQEEBQAw"
              + "bzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAk1BMRAwDgYDVQQHEwdXYWx0aGFt"
              + "MRYwFAYDVQQKEw1Gb3J1bSBTeXN0ZW1zMQswCQYDVQQLEwJRQTEcMBoGA1UE"
              + "AxMTQ2VydGlmaWNhdGUgTWFuYWdlcjAeFw0wMzAzMjEwNTAwMDBaFw0yNTAz"
              + "MjEwNTAwMDBaMCExHzAdBgNVBAMTFk9DU1AgY2VydC1RQS1DTElFTlQtODcw"
              + "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVuxRCZgJAYAftYuRy"
              + "9axdtsHrkIJyVVRorLCTWOoLmx2tlrGqKbHOGKmvqEPEpeCDYQk+0WIlWMuM"
              + "2pgiYAolwqSFBwCjkjQN3fCIHXiby0JBgCCLoe7wa0pZffE+8XZH0JdSjoT3"
              + "2OYD19wWZeY2VB0JWJFWYAnIL+R5Eg7LwJ5QZSdvghnOWKTv60m/O1rC0see"
              + "9lbPO+3jRuaDyCUKYy/YIKBYC9rtC4hS47jg70dTfmE2nccjn7rFCPBrVr4M"
              + "5szqdRzwu3riL9W+IE99LTKXOH/24JX0S4woeGXMS6me7SyZE6x7P2tYkNXM"
              + "OfXk28b3SJF75K7vX6T6ecWjAgMBAAGjKDAmMBMGA1UdJQQMMAoGCCsGAQUF"
              + "BwMJMA8GCSsGAQUFBzABBQQCBQAwDQYJKoZIhvcNAQEEBQADggEBAKNSn7pp"
              + "UEC1VTN/Iqk8Sc2cAYM7KSmeB++tuyes1iXY4xSQaEgOxRa5AvPAKnXKSzfY"
              + "vqi9WLdzdkpTo4AzlHl5nqU/NCUv3yOKI9lECVMgMxLAvZgMALS5YXNZsqrs"
              + "hP3ASPQU99+5CiBGGYa0PzWLstXLa6SvQYoHG2M8Bb2lHwgYKsyrUawcfc/s"
              + "jE3jFJeyCyNwzH0eDJUVvW1/I3AhLNWcPaT9/VfyIWu5qqZU+ukV/yQXrKiB"
              + "glY8v4QDRD4aWQlOuiV2r9sDRldOPJe2QSFDBe4NtBbynQ+MRvF2oQs/ocu+"
              + "OAHX7uiskg9GU+9cdCWPwJf9cP/Zem6MemgwggPPMIICt6ADAgECAgEBMA0G"
              + "CSqGSIb3DQEBBQUAMG8xCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJNQTEQMA4G"
              + "A1UEBxMHV2FsdGhhbTEWMBQGA1UEChMNRm9ydW0gU3lzdGVtczELMAkGA1UE"
              + "CxMCUUExHDAaBgNVBAMTE0NlcnRpZmljYXRlIE1hbmFnZXIwHhcNMDMwMzIx"
              + "MDUwMDAwWhcNMjUwMzIxMDUwMDAwWjBvMQswCQYDVQQGEwJVUzELMAkGA1UE"
              + "CBMCTUExEDAOBgNVBAcTB1dhbHRoYW0xFjAUBgNVBAoTDUZvcnVtIFN5c3Rl"
              + "bXMxCzAJBgNVBAsTAlFBMRwwGgYDVQQDExNDZXJ0aWZpY2F0ZSBNYW5hZ2Vy"
              + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4VeU+48VBjI0mGRt"
              + "9qlD+WAhx3vv4KCOD5f3HWLj8D2DcoszVTVDqtRK+HS1eSpO/xWumyXhjV55"
              + "FhG2eYi4e0clv0WyswWkGLqo7IxYn3ZhVmw04ohdTjdhVv8oS+96MUqPmvVW"
              + "+MkVRyqm75HdgWhKRr/lEpDNm+RJe85xMCipkyesJG58p5tRmAZAAyRs3jYw"
              + "5YIFwDOnt6PCme7ui4xdas2zolqOlynMuq0ctDrUPKGLlR4mVBzgAVPeatcu"
              + "ivEQdB3rR6UN4+nv2jx9kmQNNb95R1M3J9xHfOWX176UWFOZHJwVq8eBGF9N"
              + "pav4ZGBAyqagW7HMlo7Hw0FzUwIDAQABo3YwdDARBglghkgBhvhCAQEEBAMC"
              + "AJcwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU64zBxl1yKES8tjU3/rBA"
              + "NaeBpjkwHwYDVR0jBBgwFoAU64zBxl1yKES8tjU3/rBANaeBpjkwDgYDVR0P"
              + "AQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQAzHnf+Z+UgxDVOpCu0DHF+"
              + "qYZf8IaUQxLhUD7wjwnt3lJ0QV1z4oyc6Vs9J5xa8Mvf7u1WMmOxvN8r8Kb0"
              + "k8DlFszLd0Qwr+NVu5NQO4Vn01UAzCtH4oX2bgrVzotqDnzZ4TcIr11EX3Nb"
              + "tO8yWWl+xWIuxKoAO8a0Rh97TyYfAj4++GIm43b2zIvRXEWAytjz7rXUMwRC"
              + "1ipRQwSA9gyw2y0s8emV/VwJQXsTe9xtDqlEC67b90V/BgL/jxck5E8yrY9Z"
              + "gNxlOgcqscObisAkB5I6GV+dfa+BmZrhSJ/bvFMUrnFzjLFvZp/9qiK11r5K"
              + "A5oyOoNv0w+8bbtMNEc1"
              + "====");

    public String getName()
    {
        return "OCSP";
    }

    private void testECDSA()
        throws Exception
    {
        String          signDN = "O=Bouncy Castle, C=AU";
        KeyPair         signKP = OCSPTestUtil.makeECKeyPair();
        X509Certificate testCert = OCSPTestUtil.makeECDSACertificate(signKP, signDN, signKP, signDN);

        String          origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        GeneralName     origName = new GeneralName(new X509Name(origDN));

        //
        // general id value for our test issuer cert and a serial number.
        //
        CertificateID   id = new CertificateID(CertificateID.HASH_SHA1, testCert, BigInteger.valueOf(1));

        //
        // basic request generation
        //
        OCSPReqGenerator    gen = new OCSPReqGenerator();

        gen.addRequest(
                new CertificateID(CertificateID.HASH_SHA1, testCert, BigInteger.valueOf(1)));

        OCSPReq         req = gen.generate();

        if (req.isSigned())
        {
            fail("signed but shouldn't be");
        }

        X509Certificate[] certs = req.getCerts("BC");

        if (certs != null)
        {
            fail("null certs expected, but not found");
        }

        Req[]           requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // request generation with signing
        //
        X509Certificate[]   chain = new X509Certificate[1];

        gen = new OCSPReqGenerator();

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X509Principal("CN=fred")));

        gen.addRequest(
                new CertificateID(CertificateID.HASH_SHA1, testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.generate("SHA1withECDSA", signKP.getPrivate(), chain, "BC");

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.verify(signKP.getPublic(), "BC"))
        {
            fail("signature failed to verify");
        }

        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        certs = req.getCerts("BC");

        if (certs == null)
        {
            fail("null certs found");
        }

        if (certs.length != 1 || !certs[0].equals(testCert))
        {
            fail("incorrect certs found in request");
        }

        //
        // encoding test
        //
        byte[] reqEnc = req.getEncoded();

        OCSPReq newReq = new OCSPReq(reqEnc);

        if (!newReq.verify(signKP.getPublic(), "BC"))
        {
            fail("newReq signature failed to verify");
        }

        //
        // request generation with signing and nonce
        //
        chain = new X509Certificate[1];

        gen = new OCSPReqGenerator();

        Vector oids = new Vector();
        Vector values = new Vector();
        byte[] sampleNonce = new byte[16];
        Random rand = new Random();

        rand.nextBytes(sampleNonce);

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X509Principal("CN=fred")));

        oids.addElement(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        values.addElement(new X509Extension(false, new DEROctetString(new DEROctetString(sampleNonce))));

        gen.setRequestExtensions(new X509Extensions(oids, values));

        gen.addRequest(
                new CertificateID(CertificateID.HASH_SHA1, testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.generate("SHA1withECDSA", signKP.getPrivate(), chain, "BC");

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.verify(signKP.getPublic(), "BC"))
        {
            fail("signature failed to verify");
        }

        //
        // extension check.
        //
        Set extOids = req.getCriticalExtensionOIDs();

        if (extOids.size() != 0)
        {
            fail("wrong number of critical extensions in OCSP request.");
        }

        extOids = req.getNonCriticalExtensionOIDs();

        if (extOids.size() != 1)
        {
            fail("wrong number of non-critical extensions in OCSP request.");
        }

        byte[] extValue = req.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());

        ASN1Encodable extObj = X509ExtensionUtil.fromExtensionValue(extValue);

        if (!(extObj instanceof ASN1OctetString))
        {
            fail("wrong extension type found.");
        }

        if (!areEqual(((ASN1OctetString)extObj).getOctets(), sampleNonce))
        {
            fail("wrong extension value found.");
        }

        //
        // request list check
        //
        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // response generation
        //
        BasicOCSPRespGenerator respGen = new BasicOCSPRespGenerator(signKP.getPublic());

        respGen.addResponse(id, CertificateStatus.GOOD);

        respGen.generate("SHA1withECDSA", signKP.getPrivate(), chain, new Date(), "BC");
    }

    public void performTest()
        throws Exception
    {
        String          signDN = "O=Bouncy Castle, C=AU";
        KeyPair         signKP = OCSPTestUtil.makeKeyPair();
        X509Certificate testCert = OCSPTestUtil.makeCertificate(signKP, signDN, signKP, signDN);

        String          origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        GeneralName     origName = new GeneralName(new X509Name(origDN));

        //
        // general id value for our test issuer cert and a serial number.
        //
        CertificateID   id = new CertificateID(CertificateID.HASH_SHA1, testCert, BigInteger.valueOf(1));

        //
        // basic request generation
        //
        OCSPReqGenerator    gen = new OCSPReqGenerator();

        gen.addRequest(
                new CertificateID(CertificateID.HASH_SHA1, testCert, BigInteger.valueOf(1)));

        OCSPReq         req = gen.generate();

        if (req.isSigned())
        {
            fail("signed but shouldn't be");
        }

        X509Certificate[] certs = req.getCerts("BC");
        
        if (certs != null)
        {
            fail("null certs expected, but not found");
        }
        
        Req[]           requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }

        //
        // request generation with signing
        //
        X509Certificate[]   chain = new X509Certificate[1];

        gen = new OCSPReqGenerator();

        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X509Principal("CN=fred")));
        
        gen.addRequest(
                new CertificateID(CertificateID.HASH_SHA1, testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.generate("SHA1withRSA", signKP.getPrivate(), chain, "BC");

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.verify(signKP.getPublic(), "BC"))
        {
            fail("signature failed to verify");
        }

        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }
        
        certs = req.getCerts("BC");
        
        if (certs == null)
        {
            fail("null certs found");
        }
        
        if (certs.length != 1 || !certs[0].equals(testCert))
        {
            fail("incorrect certs found in request");
        }

        //
        // encoding test
        //
        byte[] reqEnc = req.getEncoded();
        
        OCSPReq newReq = new OCSPReq(reqEnc);
        
        if (!newReq.verify(signKP.getPublic(), "BC"))
        {
            fail("newReq signature failed to verify");
        }
        
        //
        // request generation with signing and nonce
        //
        chain = new X509Certificate[1];

        gen = new OCSPReqGenerator();

        Vector oids = new Vector();
        Vector values = new Vector();
        byte[] sampleNonce = new byte[16];
        Random rand = new Random();
        
        rand.nextBytes(sampleNonce);
        
        gen.setRequestorName(new GeneralName(GeneralName.directoryName, new X509Principal("CN=fred")));
        
        oids.addElement(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        values.addElement(new X509Extension(false, new DEROctetString(new DEROctetString(sampleNonce))));

        gen.setRequestExtensions(new X509Extensions(oids, values));
        
        gen.addRequest(
                new CertificateID(CertificateID.HASH_SHA1, testCert, BigInteger.valueOf(1)));

        chain[0] = testCert;

        req = gen.generate("SHA1withRSA", signKP.getPrivate(), chain, "BC");

        if (!req.isSigned())
        {
            fail("not signed but should be");
        }

        if (!req.verify(signKP.getPublic(), "BC"))
        {
            fail("signature failed to verify");
        }
        
        //
        // extension check.
        //
        Set extOids = req.getCriticalExtensionOIDs();
        
        if (extOids.size() != 0)
        {
            fail("wrong number of critical extensions in OCSP request.");
        }

        extOids = req.getNonCriticalExtensionOIDs();
        
        if (extOids.size() != 1)
        {
            fail("wrong number of non-critical extensions in OCSP request.");
        }
        
        byte[] extValue = req.getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId());
        
        ASN1Encodable extObj = X509ExtensionUtil.fromExtensionValue(extValue);
        
        if (!(extObj instanceof ASN1OctetString))
        {
            fail("wrong extension type found.");
        }
        
        if (!areEqual(((ASN1OctetString)extObj).getOctets(), sampleNonce))
        {
            fail("wrong extension value found.");
        }
        
        //
        // request list check
        //
        requests = req.getRequestList();

        if (!requests[0].getCertID().equals(id))
        {
            fail("Failed isFor test");
        }
        
        //
        // response parsing - test 1
        //
        OCSPResp    response = new OCSPResp(new ByteArrayInputStream(testResp1));

        if (response.getStatus() != 0)
        {
            fail("response status not zero.");
        }

        BasicOCSPResp       brep = (BasicOCSPResp)response.getResponseObject();
        chain = brep.getCerts("BC");

        if (!brep.verify(chain[0].getPublicKey(), "BC"))
        {
            fail("response 1 failed to verify.");
        }

        //
        // test 2
        //
        SingleResp[]        singleResp = brep.getResponses();

        response = new OCSPResp(new ByteArrayInputStream(testResp2));

        if (response.getStatus() != 0)
        {
            fail("response status not zero.");
        }

        brep = (BasicOCSPResp)response.getResponseObject();
        chain = brep.getCerts("BC");

        if (!brep.verify(chain[0].getPublicKey(), "BC"))
        {
            fail("response 2 failed to verify.");
        }

        singleResp = brep.getResponses();
        
        //
        // simple response generation
        //
        OCSPRespGenerator respGen = new OCSPRespGenerator();
        OCSPResp resp = respGen.generate(OCSPRespGenerator.SUCCESSFUL, response.getResponseObject());

        if (!resp.getResponseObject().equals(response.getResponseObject()))
        {
            fail("response fails to match");
        }

        testECDSA();
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new OCSPTest());
    }
}
