package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;

public class SMIMESignedTest
    extends TestCase
{

    boolean DEBUG = true;

    MimeBodyPart    msg;

    String          signDN;
    KeyPair         signKP;
    X509Certificate signCert;

    String          origDN;
    KeyPair         origKP;
    X509Certificate origCert;

    String          reciDN;
    KeyPair         reciKP;
    X509Certificate reciCert;

    KeyPair         dsaSignKP;
    X509Certificate dsaSignCert;

    KeyPair         dsaOrigKP;
    X509Certificate dsaOrigCert;

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public SMIMESignedTest(String name) {
        super(name);
    }

    public static void main(String args[]) {
        MailcapCommandMap _mailcap =
                           (MailcapCommandMap)CommandMap.getDefaultCommandMap();

        _mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        _mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        _mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        _mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        _mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

        CommandMap.setDefaultCommandMap(_mailcap);

        junit.textui.TestRunner.run(SMIMESignedTest.class);
    }

    public static Test suite() {
        return new SMIMETestSetup(new TestSuite(SMIMESignedTest.class));
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
        if (msg == null)
        {
            try
            {
                msg      = SMIMETestUtil.makeMimeBodyPart("Hello world!");
    
                signDN   = "O=Bouncy Castle, C=AU";
                signKP   = SMIMETestUtil.makeKeyPair();  
                signCert = SMIMETestUtil.makeCertificate(signKP, signDN, signKP, signDN);
    
                origDN   = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
                origKP   = SMIMETestUtil.makeKeyPair();
                origCert = SMIMETestUtil.makeCertificate(origKP, origDN, signKP, signDN);
            }
            catch(Exception ex)
            {
                log(ex);
                fail();
            }
        }
    }

    public void tearDown() {

    }

    /*
     *
     *  TESTS
     *
     */

    public void testSHA1WithRSA()
    {
        try
        {
            ArrayList           certList = new ArrayList();

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
            SMIMECapabilityVector       caps = new SMIMECapabilityVector();

            caps.addCapability(SMIMECapability.dES_EDE3_CBC);
            caps.addCapability(SMIMECapability.rC2_CBC, 128);
            caps.addCapability(SMIMECapability.dES_CBC);

            signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

            SMIMESignedGenerator gen = new SMIMESignedGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);

            gen.addCertificatesAndCRLs(certs);

            MimeMultipart _smm = gen.generate(msg, "BC");
            MimeBodyPart  _res = (MimeBodyPart)_smm.getBodyPart(0);
            
            SMIMESigned s = new SMIMESigned(_smm);

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            s.getContent().writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));

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

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
            SMIMECapabilityVector       caps = new SMIMECapabilityVector();

            caps.addCapability(SMIMECapability.dES_EDE3_CBC);
            caps.addCapability(SMIMECapability.rC2_CBC, 128);
            caps.addCapability(SMIMECapability.dES_CBC);

            signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

            SMIMESignedGenerator gen = new SMIMESignedGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);

            gen.addCertificatesAndCRLs(certs);

            MimeBodyPart res = gen.generateEncapsulated(msg, "BC");
            
            SMIMESigned s = new SMIMESigned(res);

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            s.getContent().writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));

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
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
    
    public void testMD5WithRSA()
    {
        try {
            ArrayList           certList = new ArrayList();

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            SMIMESignedGenerator gen = new SMIMESignedGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_MD5);
            gen.addCertificatesAndCRLs(certs);


            MimeMultipart _smm = gen.generate(msg, "BC");
            MimeBodyPart  _res = (MimeBodyPart)_smm.getBodyPart(0);
            
            SMIMESigned s = new  SMIMESigned(_smm);

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            s.getContent().writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));

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
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }

    public void testSHA224WithRSA()
    {
        try {
            ArrayList           certList = new ArrayList();

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            SMIMESignedGenerator gen = new SMIMESignedGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA224);
            gen.addCertificatesAndCRLs(certs);


            MimeMultipart _smm = gen.generate(msg, "BC");
            MimeBodyPart  _res = (MimeBodyPart)_smm.getBodyPart(0);
            
            SMIMESigned s = new  SMIMESigned(_smm);

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            s.getContent().writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));

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
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }

    public void testSHA1withDSA()
    {
        try {
            dsaSignKP   = SMIMETestUtil.makeDSAKeyPair();  
            dsaSignCert = SMIMETestUtil.makeCertificate(dsaSignKP, signDN, dsaSignKP, signDN);

            dsaOrigKP   = SMIMETestUtil.makeDSAKeyPair();
            dsaOrigCert = SMIMETestUtil.makeCertificate(dsaOrigKP, origDN, dsaSignKP, signDN);

            ArrayList           certList = new ArrayList();

            certList.add(dsaOrigCert);
            certList.add(dsaSignCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            SMIMESignedGenerator gen = new SMIMESignedGenerator();

            gen.addSigner(dsaOrigKP.getPrivate(), dsaOrigCert, SMIMESignedGenerator.DIGEST_SHA1);
            gen.addCertificatesAndCRLs(certs);


            MimeMultipart _smm = gen.generate(msg, "BC");
            MimeBodyPart  _res = (MimeBodyPart)_smm.getBodyPart(0);
            
            SMIMESigned s = new  SMIMESigned(_smm);

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            s.getContent().writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));

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
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
    
    public void testSHA256WithRSABinary()
    {
        try
        {
            ArrayList           certList = new ArrayList();

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
            SMIMECapabilityVector       caps = new SMIMECapabilityVector();

            caps.addCapability(SMIMECapability.dES_EDE3_CBC);
            caps.addCapability(SMIMECapability.rC2_CBC, 128);
            caps.addCapability(SMIMECapability.dES_CBC);

            signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

            SMIMESignedGenerator gen = new SMIMESignedGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA256, new AttributeTable(signedAttrs), null);

            gen.addCertificatesAndCRLs(certs);

            InternetHeaders ih = new InternetHeaders();
            
            ih.setHeader("Content-Transfer-Encoding", "binary");
            
            byte[] content = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 10, 11, 12, 13, 14, 10, 10, 15, 16 };
            
            MimeBodyPart  msg = new MimeBodyPart(ih, content);
            MimeMultipart _smm = gen.generate(msg, "BC");
            MimeBodyPart  _res = (MimeBodyPart)_smm.getBodyPart(0);
            
            SMIMESigned s = new  SMIMESigned(_smm);

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            s.getContent().writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));

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
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }

    public void testCertificateManagement()
    {
        try
        {
            ArrayList           certList = new ArrayList();

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                            new CollectionCertStoreParameters(certList), "BC");

            SMIMESignedGenerator gen = new SMIMESignedGenerator();

            gen.addCertificatesAndCRLs(certs);
            
            MimeBodyPart smm = gen.generateCertificateManagement("BC");

            SMIMESigned s = new  SMIMESigned(smm);

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            assertEquals(2, certs.getCertificates(null).size());
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
}
