package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedParser;

public class SMIMESignedTest
    extends TestCase
{
    static MimeBodyPart    msg;
    
    static MimeBodyPart    msgR;
    static MimeBodyPart    msgRN;

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
            
            msgR     = SMIMETestUtil.makeMimeBodyPart("Hello world!\r");
            msgRN    = SMIMETestUtil.makeMimeBodyPart("Hello world!\r\n");
            
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

    public SMIMESignedTest(String name)
    {
        super(name);
    }

    public static void main(String args[]) 
    {
        junit.textui.TestRunner.run(SMIMESignedTest.class);
    }

    public static Test suite() 
    {
        return new SMIMETestSetup(new TestSuite(SMIMESignedTest.class));
    }
    
    public void testHeaders()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msg);
        BodyPart      bp = smm.getBodyPart(1);

        assertEquals("application/pkcs7-signature; name=smime.p7s; smime-type=signed-data", bp.getHeader("Content-Type")[0]);
        assertEquals("attachment; filename=\"smime.p7s\"", bp.getHeader("Content-Disposition")[0]);
        assertEquals("S/MIME Cryptographic Signature", bp.getHeader("Content-Description")[0]);
    }

    public void testHeadersEncapsulated()
        throws Exception
    {
        List           certList = new ArrayList();

        certList.add(origCert);
        certList.add(signCert);

        CertStore           certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        ASN1EncodableVector signedAttrs = generateSignedAttributes();

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);

        gen.addCertificatesAndCRLs(certs);

        MimeBodyPart res = gen.generateEncapsulated(msg, "BC");

        assertEquals("application/pkcs7-mime; name=smime.p7m; smime-type=signed-data", res.getHeader("Content-Type")[0]);
        assertEquals("attachment; filename=\"smime.p7m\"", res.getHeader("Content-Disposition")[0]);
        assertEquals("S/MIME Cryptographic Signed Data", res.getHeader("Content-Description")[0]);
    }
    
    public void testSHA1WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msg);          
        SMIMESigned   s = new SMIMESigned(smm);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }
    
    public void testSHA1WithRSACanonicalization()
        throws Exception
    {
        Date          testTime = new Date();
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msg, testTime); 
        
        byte[] sig1 = getEncodedStream(smm);
    
        smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msgR, testTime);          

        byte[] sig2 = getEncodedStream(smm);

        assertTrue(Arrays.equals(sig1, sig2));
        
        smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA1, msgRN, testTime);          

        byte[] sig3 = getEncodedStream(smm);

        assertTrue(Arrays.equals(sig1, sig3));
    }

    private byte[] getEncodedStream(MimeMultipart smm) 
        throws IOException, MessagingException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        smm.getBodyPart(1).writeTo(bOut);

        return bOut.toByteArray();
    }
    
    public void testSHA1WithRSAEncapsulated()
        throws Exception
    {
        MimeBodyPart res = generateEncapsulatedRsa(SMIMESignedGenerator.DIGEST_SHA1, msg);
        SMIMESigned  s = new SMIMESigned(res);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }
    
    public void testSHA1WithRSAEncapsulatedParser()
        throws Exception
    {
        MimeBodyPart res = generateEncapsulatedRsa(SMIMESignedGenerator.DIGEST_SHA1, msg);       
        SMIMESignedParser s = new SMIMESignedParser(res);

        verifyMessageBytes(msg, s.getContent());
    
        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testMD5WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_MD5, msg);       
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals(getDigestOid(s.getSignerInfos()), PKCSObjectIdentifiers.md5.toString());
        
        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA224WithRSA()
        throws Exception
    {
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA224, msg);  
        SMIMESigned   s = new  SMIMESigned(smm);

        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha224.toString());
        
        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA224WithRSAParser()
        throws Exception
    {
        MimeMultipart     smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA224, msg);
        SMIMESignedParser s = new SMIMESignedParser(smm);
        CertStore         certs = s.getCertificatesAndCRLs("Collection", "BC");
        
        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha224.toString());
        
        verifyMessageBytes(msg, s.getContent());
    
        verifySigners(certs, s.getSignerInfos());
    }
    
    public void testSHA224WithRSAParserEncryptedWithDES()
        throws Exception
    {
        List certList = new ArrayList();
        
        certList.add(origCert);
        certList.add(signCert);
    
        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        ASN1EncodableVector signedAttrs = generateSignedAttributes();
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
    
        gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA224, new AttributeTable(signedAttrs), null);   
        gen.addCertificatesAndCRLs(certs);

        MimeMultipart     smm = gen.generate(msg, "BC");
        SMIMESignedParser s = new SMIMESignedParser(smm);
        
        certs = s.getCertificatesAndCRLs("Collection", "BC");
        
        assertEquals(getDigestOid(s.getSignerInfos()), NISTObjectIdentifiers.id_sha224.toString());
        
        verifyMessageBytes(msg, s.getContent());
    
        verifySigners(certs, s.getSignerInfos());
    }
    
    public void testSHA1withDSA()
        throws Exception
    {
        dsaSignKP   = SMIMETestUtil.makeDSAKeyPair();  
        dsaSignCert = SMIMETestUtil.makeCertificate(dsaSignKP, signDN, dsaSignKP, signDN);

        dsaOrigKP   = SMIMETestUtil.makeDSAKeyPair();
        dsaOrigCert = SMIMETestUtil.makeCertificate(dsaOrigKP, origDN, dsaSignKP, signDN);

        List           certList = new ArrayList();

        certList.add(dsaOrigCert);
        certList.add(dsaSignCert);

        CertStore      certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");

        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        gen.addSigner(dsaOrigKP.getPrivate(), dsaOrigCert, SMIMESignedGenerator.DIGEST_SHA1);
        gen.addCertificatesAndCRLs(certs);


        MimeMultipart smm = gen.generate(msg, "BC");
        SMIMESigned   s = new  SMIMESigned(smm);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }
    
    public void testSHA256WithRSABinary()
        throws Exception
    {
        MimeBodyPart  msg = generateBinaryPart();
        MimeMultipart smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA256, msg);
        SMIMESigned   s = new  SMIMESigned(smm);

        verifyMessageBytes(msg, s.getContent());

        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    public void testSHA256WithRSABinaryWithParser()
        throws Exception
    {
        MimeBodyPart      msg = generateBinaryPart();
        MimeMultipart     smm = generateMultiPartRsa(SMIMESignedGenerator.DIGEST_SHA256, msg);
        SMIMESignedParser s = new SMIMESignedParser(smm);
    
        verifyMessageBytes(msg, s.getContent());
    
        verifySigners(s.getCertificatesAndCRLs("Collection", "BC"), s.getSignerInfos());
    }

    private MimeBodyPart generateBinaryPart() throws MessagingException
    {
        byte[] content = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 10, 11, 12, 13, 14, 10, 10, 15, 16 };   
        InternetHeaders ih = new InternetHeaders();
        
        ih.setHeader("Content-Transfer-Encoding", "binary");
        MimeBodyPart  msg = new MimeBodyPart(ih, content);
        
        return msg;
    }
    
    private MimeMultipart generateMultiPartRsa(
        String digestOid, 
        MimeBodyPart msg,
        Date         signingTime) 
        throws Exception
    {
        List certList = new ArrayList();
    
        certList.add(origCert);
        certList.add(signCert);
    
        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        ASN1EncodableVector signedAttrs = generateSignedAttributes();
        
        if (signingTime != null)
        {
            signedAttrs.add(new Attribute(CMSAttributes.signingTime, new DERSet(new Time(signingTime))));
        }
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
    
        gen.addSigner(origKP.getPrivate(), origCert, digestOid, new AttributeTable(signedAttrs), null);   
        gen.addCertificatesAndCRLs(certs);

        return gen.generate(msg, "BC");
    }
    
    private MimeMultipart generateMultiPartRsa(String digestOid, MimeBodyPart msg) 
        throws Exception
    {
        return generateMultiPartRsa(digestOid, msg, null);
    }
    
    private MimeBodyPart generateEncapsulatedRsa(String digestOid, MimeBodyPart msg) 
        throws Exception
    {
        List certList = new ArrayList();
    
        certList.add(origCert);
        certList.add(signCert);
    
        CertStore certs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(certList), "BC");
    
        ASN1EncodableVector signedAttrs = generateSignedAttributes();
    
        SMIMESignedGenerator gen = new SMIMESignedGenerator();
    
        gen.addSigner(origKP.getPrivate(), origCert, digestOid, new AttributeTable(signedAttrs), null);   
        gen.addCertificatesAndCRLs(certs);
    
        return gen.generateEncapsulated(msg, "BC");
    }
    
    public void testCertificateManagement()
        throws Exception
    {
        List           certList = new ArrayList();

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
    
    private String getDigestOid(SignerInformationStore s)
    {
        return ((SignerInformation)s.getSigners().iterator().next()).getDigestAlgOID();
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
