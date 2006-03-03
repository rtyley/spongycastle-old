package org.bouncycastle.cms.test;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.encoders.Base64;

public class SignedDataStreamTest
    extends TestCase
{
    private static final String TEST_MESSAGE = "Hello World!";
    private static String          _signDN;
    private static KeyPair         _signKP;  
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;
    
    private static KeyPair         _origDsaKP;
    private static X509Certificate _origDsaCert;
    
    private static boolean _initialised = false;
    
    public SignedDataStreamTest(String name) 
    {
        super(name);
    }
    
    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            
            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();  
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);
    
            _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);
    
            _origDsaKP   = CMSTestUtil.makeDsaKeyPair();
            _origDsaCert = CMSTestUtil.makeCertificate(_origDsaKP, _origDN, _signKP, _signDN);
            
            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);  
        }
    }
    
    private void verifySignatures(CMSSignedDataParser sp, byte[] contentDigest) 
        throws Exception
    {
        CertStore               certs = sp.getCertificatesAndCRLs("Collection", "BC");
        SignerInformationStore  signers = sp.getSignerInfos();
        
        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();
    
        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certs.getCertificates(signer.getSID());
    
            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate)certIt.next();
    
            assertEquals(true, signer.verify(cert, "BC"));
            
            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }
    }
    
    private void verifySignatures(CMSSignedDataParser sp) 
        throws Exception
    {
        verifySignatures(sp, null);
    }

    private void verifyEncodedData(ByteArrayOutputStream bOut) throws CMSException, IOException, Exception
    {
        CMSSignedDataParser sp;
        sp = new CMSSignedDataParser(bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        verifySignatures(sp);
    }
    
    public void testSha1EncapsulatedSignature()
        throws Exception
    {
        byte[]  encapSigData = Base64.decode(
                  "MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEH"
                + "AaCAJIAEDEhlbGxvIFdvcmxkIQAAAAAAAKCCBGIwggINMIIBdqADAgECAgEF"
                + "MA0GCSqGSIb3DQEBBAUAMCUxFjAUBgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJ"
                + "BgNVBAYTAkFVMB4XDTA1MDgwNzA2MjU1OVoXDTA1MTExNTA2MjU1OVowJTEW"
                + "MBQGA1UEChMNQm91bmN5IENhc3RsZTELMAkGA1UEBhMCQVUwgZ8wDQYJKoZI"
                + "hvcNAQEBBQADgY0AMIGJAoGBAI1fZGgH9wgC3QiK6yluH6DlLDkXkxYYL+Qf"
                + "nVRszJVYl0LIxZdpb7WEbVpO8fwtEgFtoDsOdxyqh3dTBv+L7NVD/v46kdPt"
                + "xVkSNHRbutJVY8Xn4/TC/CDngqtbpbniMO8n0GiB6vs94gBT20M34j96O2IF"
                + "73feNHP+x8PkJ+dNAgMBAAGjTTBLMB0GA1UdDgQWBBQ3XUfEE6+D+t+LIJgK"
                + "ESSUE58eyzAfBgNVHSMEGDAWgBQ3XUfEE6+D+t+LIJgKESSUE58eyzAJBgNV"
                + "HRMEAjAAMA0GCSqGSIb3DQEBBAUAA4GBAFK3r1stYOeXYJOlOyNGDTWEhZ+a"
                + "OYdFeFaS6c+InjotHuFLAy+QsS8PslE48zYNFEqYygGfLhZDLlSnJ/LAUTqF"
                + "01vlp+Bgn/JYiJazwi5WiiOTf7Th6eNjHFKXS3hfSGPNPIOjvicAp3ce3ehs"
                + "uK0MxgLAaxievzhFfJcGSUMDMIICTTCCAbagAwIBAgIBBzANBgkqhkiG9w0B"
                + "AQQFADAlMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTAe"
                + "Fw0wNTA4MDcwNjI1NTlaFw0wNTExMTUwNjI1NTlaMGUxGDAWBgNVBAMTD0Vy"
                + "aWMgSC4gRWNoaWRuYTEkMCIGCSqGSIb3DQEJARYVZXJpY0Bib3VuY3ljYXN0"
                + "bGUub3JnMRYwFAYDVQQKEw1Cb3VuY3kgQ2FzdGxlMQswCQYDVQQGEwJBVTCB"
                + "nzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgHCJyfwV6/V3kqSu2SOU2E/K"
                + "I+N0XohCMUaxPLLNtNBZ3ijxwaV6JGFz7siTgZD/OGfzir/eZimkt+L1iXQn"
                + "OAB+ZChivKvHtX+dFFC7Vq+E4Uy0Ftqc/wrGxE6DHb5BR0hprKH8wlDS8wSP"
                + "zxovgk4nH0ffUZOoDSuUgjh3gG8CAwEAAaNNMEswHQYDVR0OBBYEFLfY/4EG"
                + "mYrvJa7Cky+K9BJ7YmERMB8GA1UdIwQYMBaAFDddR8QTr4P634sgmAoRJJQT"
                + "nx7LMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEEBQADgYEADIOmpMd6UHdMjkyc"
                + "mIE1yiwfClCsGhCK9FigTg6U1G2FmkBwJIMWBlkeH15uvepsAncsgK+Cn3Zr"
                + "dZMb022mwtTJDtcaOM+SNeuCnjdowZ4i71Hf68siPm6sMlZkhz49rA0Yidoo"
                + "WuzYOO+dggzwDsMldSsvsDo/ARyCGOulDOAxggEvMIIBKwIBATAqMCUxFjAU"
                + "BgNVBAoTDUJvdW5jeSBDYXN0bGUxCzAJBgNVBAYTAkFVAgEHMAkGBSsOAwIa"
                + "BQCgXTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEP"
                + "Fw0wNTA4MDcwNjI1NTlaMCMGCSqGSIb3DQEJBDEWBBQu973mCM5UBOl9XwQv"
                + "lfifHCMocTANBgkqhkiG9w0BAQEFAASBgGxnBl2qozYKLgZ0ygqSFgWcRGl1"
                + "LgNuE587LtO+EKkgoc3aFqEdjXlAyP8K7naRsvWnFrsB6pUpnrgI9Z8ZSKv8"
                + "98IlpsSSJ0jBlEb4gzzavwcBpYbr2ryOtDcF+kYmKIpScglyyoLzm+KPXOoT"
                + "n7MsJMoKN3Kd2Vzh6s10PFgeAAAAAAAA");

        CMSSignedDataParser     sp = new CMSSignedDataParser(encapSigData);

        sp.getSignedContent().drain();

        verifySignatures(sp);
    }
    
    public void testSHA1WithRSANoAttributes()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSProcessable      msg = new CMSProcessableByteArray(TEST_MESSAGE.getBytes());
    
        certList.add(_origCert);
        certList.add(_signCert);
    
        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataGenerator.DIGEST_SHA1);
    
        gen.addCertificatesAndCRLs(certs);
    
        CMSSignedData s = gen.generate(CMSSignedDataGenerator.DATA, msg, false, "BC", false);

        CMSSignedDataParser     sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), s.getEncoded());
        
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", "BC");
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
    }
    
    public void testDSANoAttributes()
        throws Exception
    {
        List                certList = new ArrayList();
        CMSProcessable      msg = new CMSProcessableByteArray(TEST_MESSAGE.getBytes());
    
        certList.add(_origDsaCert);
        certList.add(_signCert);
    
        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    
        gen.addSigner(_origDsaKP.getPrivate(), _origDsaCert, CMSSignedDataGenerator.DIGEST_SHA1);
    
        gen.addCertificatesAndCRLs(certs);
    
        CMSSignedData s = gen.generate(CMSSignedDataGenerator.DATA, msg, false, "BC", false);
    
        CMSSignedDataParser     sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), s.getEncoded());
        
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", "BC");
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
    }
    
    public void testSHA1WithRSA()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);
    
        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
    
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "BC");
    
        gen.addCertificatesAndCRLs(certs);
    
        OutputStream sigOut = gen.open(bOut);
    
        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(TEST_MESSAGE.getBytes())), bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        //
        // compute expected content digest
        //
        MessageDigest md = MessageDigest.getInstance("SHA1", "BC");
        
        verifySignatures(sp, md.digest(TEST_MESSAGE.getBytes()));
        
        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();
    
        gen.addSigners(sp.getSignerInfos());
        
        gen.addCertificatesAndCRLs(sp.getCertificatesAndCRLs("Collection", "BC"));
        
        bOut.reset();
        
        sigOut = gen.open(bOut, true);
    
        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();
    
        verifyEncodedData(bOut);
    }
    
    public void testSHA1WithRSAEncapsulatedBufferedStream()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                               new CollectionCertStoreParameters(certList), "BC");

        //
        // find unbuffered length
        //
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "BC");

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);
        
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        int unbufferedLength = bOut.toByteArray().length;
        
        //
        // find buffered length
        //
        bOut = new ByteArrayOutputStream();

        gen = new CMSSignedDataStreamGenerator();
        
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "BC");

        gen.addCertificatesAndCRLs(certs);

        sigOut = gen.open(bOut, true);

        BufferedOutputStream bfOut = new BufferedOutputStream(sigOut, 300);
        
        for (int i = 0; i != 2000; i++)
        {
            bfOut.write(i & 0xff);
        }
        
        bfOut.close();
        
        verifyEncodedData(bOut);
        
        assertTrue(bOut.toByteArray().length < unbufferedLength);
    }

    public void testSHA1WithRSAEncapsulatedBuffered()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);
    
        CertStore           certs = CertStore.getInstance("Collection",
                               new CollectionCertStoreParameters(certList), "BC");
    
        //
        // find unbuffered length
        //
        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
    
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "BC");
    
        gen.addCertificatesAndCRLs(certs);
    
        OutputStream sigOut = gen.open(bOut, true);
        
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());
    
        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        int unbufferedLength = bOut.toByteArray().length;
        
        //
        // find buffered length
        //
        bOut = new ByteArrayOutputStream();
    
        gen = new CMSSignedDataStreamGenerator();
        
        gen.setBufferSize(300);
        
        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "BC");
    
        gen.addCertificatesAndCRLs(certs);
    
        sigOut = gen.open(bOut, true);
    
        for (int i = 0; i != 2000; i++)
        {
            sigOut.write(i & 0xff);
        }
        
        sigOut.close();
        
        verifyEncodedData(bOut);

        assertTrue(bOut.toByteArray().length < unbufferedLength);
    }
    
    public void testSHA1WithRSAEncapsulated()
        throws Exception
    {
        List                  certList = new ArrayList();
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        certList.add(_origCert);
        certList.add(_signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

        gen.addSigner(_origKP.getPrivate(), _origCert, CMSSignedDataStreamGenerator.DIGEST_SHA1, "BC");

        gen.addCertificatesAndCRLs(certs);

        OutputStream sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();
        
        CMSSignedDataParser     sp = new CMSSignedDataParser(bOut.toByteArray());

        sp.getSignedContent().drain();
        
        verifySignatures(sp);
        
        //
        // try using existing signer
        //
        gen = new CMSSignedDataStreamGenerator();

        gen.addSigners(sp.getSignerInfos());
        
        gen.addCertificatesAndCRLs(sp.getCertificatesAndCRLs("Collection", "BC"));
        
        bOut.reset();
        
        sigOut = gen.open(bOut, true);

        sigOut.write(TEST_MESSAGE.getBytes());
        
        sigOut.close();

        verifyEncodedData(bOut);
    }
    
    public static Test suite() 
        throws Exception
    {
        init();
        
        return new CMSTestSetup(new TestSuite(SignedDataStreamTest.class));
    }
}
