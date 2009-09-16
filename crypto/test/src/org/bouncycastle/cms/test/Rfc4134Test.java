package org.bouncycastle.cms.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

public class Rfc4134Test
    extends TestCase
{

    private static byte[] exContent = getRfc4134Data("ExContent.bin");
    private static byte[] sha1 = Hex.decode("406aec085279ba6e16022d9e0629c0229687dd48");

    public Rfc4134Test(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {

        junit.textui.TestRunner.run(Rfc4134Test.class);
    }

    public static Test suite() 
        throws Exception
    {
        return new CMSTestSetup(new TestSuite(Rfc4134Test.class));
    }

    public void test4_1()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.1.bin");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData);

        CMSSignedDataParser parser = new CMSSignedDataParser(data);

        verifySignatures(parser);
    }

    public void test4_2()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.2.bin");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData);

        CMSSignedDataParser parser = new CMSSignedDataParser(data);

        verifySignatures(parser);
    }

    public void testRfc4_3()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.3.bin");
        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(exContent), data);

        verifySignatures(signedData, sha1);

        CMSSignedDataParser parser = new CMSSignedDataParser(
                new CMSTypedStream(new ByteArrayInputStream(exContent)),
                data);

        verifySignatures(parser);
    }

    public void test4_4()
        throws Exception
    {
        byte[] data = getRfc4134Data("4.4.bin");
        byte[] counterSigCert = getRfc4134Data("AliceRSASignByCarl.cer");
        CMSSignedData signedData = new CMSSignedData(data);

        verifySignatures(signedData);

        verifySignerInfo4_4(getFirstSignerInfo(signedData.getSignerInfos()), counterSigCert);

        CMSSignedDataParser parser = new CMSSignedDataParser(data);

        verifySignatures(parser);

        verifySignerInfo4_4(getFirstSignerInfo(parser.getSignerInfos()), counterSigCert);
    }

    private void verifySignerInfo4_4(SignerInformation signerInfo, byte[] counterSigCert)
        throws Exception
    {
        verifyCounterSignature(signerInfo, counterSigCert);

        verifyContentHint(signerInfo);
    }

    private SignerInformation getFirstSignerInfo(SignerInformationStore store)
    {
        return (SignerInformation)store.getSigners().iterator().next();
    }

    private void verifyCounterSignature(SignerInformation signInfo, byte[] certificate)
        throws Exception
    {
        SignerInformation csi = (SignerInformation)signInfo.getCounterSignatures().getSigners().iterator().next();

        CertificateFactory certFact = CertificateFactory.getInstance("X.509", "BC");
        X509Certificate    cert = (X509Certificate)certFact.generateCertificate(new ByteArrayInputStream(certificate));

        assertTrue(csi.verify(cert,  "BC"));
    }

    private void verifyContentHint(SignerInformation signInfo)
    {
        AttributeTable attrTable = signInfo.getUnsignedAttributes();

        Attribute attr = attrTable.get(CMSAttributes.contentHint);

        assertEquals(1, attr.getAttrValues().size());

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERUTF8String("Content Hints Description Buffer"));
        v.add(CMSObjectIdentifiers.data);
        
        assertTrue(attr.getAttrValues().getObjectAt(0).equals(new DERSequence(v)));
    }

    private void verifySignatures(CMSSignedData s, byte[] contentDigest)
        throws Exception
    {
        CertStore               certStore = s.getCertificatesAndCRLs("Collection", "BC");
        SignerInformationStore  signers = s.getSignerInfos();

        Collection              c = signers.getSigners();
        Iterator                it = c.iterator();

        while (it.hasNext())
        {
            SignerInformation   signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getCertificates(signer.getSID());

            Iterator        certIt = certCollection.iterator();
            X509Certificate cert = (X509Certificate)certIt.next();

            assertEquals(true, signer.verify(cert, "BC"));

            if (contentDigest != null)
            {
                assertTrue(MessageDigest.isEqual(contentDigest, signer.getContentDigest()));
            }
        }

        Collection certColl = certStore.getCertificates(null);
        Collection crlColl = certStore.getCRLs(null);

        assertEquals(certColl.size(), s.getCertificates("Collection", "BC").getMatches(null).size());
        assertEquals(crlColl.size(), s.getCRLs("Collection", "BC").getMatches(null).size());
    }

    private void verifySignatures(CMSSignedData s)
        throws Exception
    {
        verifySignatures(s, null);
    }

    private void verifySignatures(CMSSignedDataParser sp)
        throws Exception
    {
        CMSTypedStream sc = sp.getSignedContent();
        if (sc != null)
        {
            sc.drain();
        }
        
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
        }
    }

    private static byte[] getRfc4134Data(String name)
    {
        try
        {
            return Streams.readAll(Rfc4134Test.class.getResourceAsStream("/rfc4134/" + name));
        }
        catch (IOException e)
        {
            throw new RuntimeException(e.toString());
        }
    }
}
