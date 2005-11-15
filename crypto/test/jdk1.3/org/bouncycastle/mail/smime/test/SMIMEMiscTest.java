package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.Security;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMECompressedGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedParser;

public class SMIMEMiscTest
    extends TestCase
{
    static MimeBodyPart    msg;

    static String          signDN;
    static KeyPair         signKP;
    static X509Certificate signCert;

    static String          origDN;
    static KeyPair         origKP;
    static X509Certificate origCert;

    static String          reciDN;
    static KeyPair         reciKP;
    static X509Certificate reciCert;

    KeyPair         dsaSignKP;
    X509Certificate dsaSignCert;

    KeyPair         dsaOrigKP;
    X509Certificate dsaOrigCert;
    
    static
    {
        try
        {
            msg      = SMIMETestUtil.makeMimeBodyPart("Hello world!\n");
            
            signDN   = "O=Bouncy Castle, C=AU";
            signKP   = SMIMETestUtil.makeKeyPair();  
            signCert = SMIMETestUtil.makeCertificate(signKP, signDN, signKP, signDN);
    
            origDN   = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
            origKP   = SMIMETestUtil.makeKeyPair();
            origCert = SMIMETestUtil.makeCertificate(origKP, origDN, signKP, signDN);
        }
        catch (Exception e)
        {
            throw new RuntimeException("problem setting up signed test class: " + e);
        }
    }

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public SMIMEMiscTest(String name)
    {
        super(name);
    }

    public static void main(String args[]) 
    {
        Security.addProvider(new BouncyCastleProvider());
        
        junit.textui.TestRunner.run(SMIMEMiscTest.class);
    }

    public static Test suite() 
    {
        return new SMIMETestSetup(new TestSuite(SMIMEMiscTest.class));
    }
    
    public void testSHA256WithRSAParserEncryptedWithAES()
        throws Exception
    {
        List certList = new ArrayList();
        
        certList.add(origCert);
        certList.add(signCert);
    
        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        SMIMEEnvelopedGenerator  encGen = new SMIMEEnvelopedGenerator();
        
        encGen.addKeyTransRecipient(origCert);

        MimeBodyPart   mp = encGen.generate(msg, SMIMEEnvelopedGenerator.AES128_CBC, "BC");
        ASN1EncodableVector signedAttrs = generateSignedAttributes();
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
    
        gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA256, new AttributeTable(signedAttrs), null);   
        gen.addCertificatesAndCRLs(certs);

        MimeMultipart     smm = gen.generate(mp, "BC");
        SMIMESignedParser s = new SMIMESignedParser(smm);

        certs = s.getCertificatesAndCRLs("Collection", "BC");

        verifyMessageBytes(mp, s.getContent());
    
        verifySigners(certs, s.getSignerInfos());
    }
    
    public void testSHA256WithRSAParserCompressed()
        throws Exception
    {
        List certList = new ArrayList();
        
        certList.add(origCert);
        certList.add(signCert);
    
        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        SMIMECompressedGenerator  cGen = new SMIMECompressedGenerator();
        
        MimeBodyPart   mp = cGen.generate(msg, SMIMECompressedGenerator.ZLIB);
        
        ASN1EncodableVector signedAttrs = generateSignedAttributes();
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
    
        gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA256, new AttributeTable(signedAttrs), null);   
        gen.addCertificatesAndCRLs(certs);
    
        MimeMultipart     smm = gen.generate(mp, "BC");
        SMIMESignedParser s = new SMIMESignedParser(smm);
        
        certs = s.getCertificatesAndCRLs("Collection", "BC");
    
        verifyMessageBytes(mp, s.getContent());
    
        verifySigners(certs, s.getSignerInfos());
    }

    private void verifySigners(CertStore certs, SignerInformationStore signers) 
        throws Exception
    {
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
    
    private void verifyMessageBytes(MimeBodyPart a, MimeBodyPart b) 
        throws Exception
    {
        ByteArrayOutputStream bOut1 = new ByteArrayOutputStream();
        
        a.writeTo(bOut1);
        bOut1.close();
        
        ByteArrayOutputStream bOut2 = new ByteArrayOutputStream();
        
        b.writeTo(bOut2);
        bOut2.close();
        
        assertEquals(true, Arrays.equals(bOut1.toByteArray(), bOut2.toByteArray()));
    }
    

    private ASN1EncodableVector generateSignedAttributes()
    {
        ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector       caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));
        
        return signedAttrs;
    }
}
