package org.bouncycastle.cert.crmf.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.crmf.PKMACValueGenerator;
import org.bouncycastle.cert.crmf.PKMACValueVerifier;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaPKIArchiveControlBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaPKMACValuesCalculator;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public AllTests(String name)
    {
        super(name);
    }

    public static void main(String args[])
    {
        junit.textui.TestRunner.run(AllTests.class);
    }

    public static Test suite()
    {
        return new TestSuite(AllTests.class);
    }

    public void setUp()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public void tearDown()
    {

    }

    public void testBasicMessage()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setSubject(new X500Principal("CN=Test"))
                    .setPublicKey(kp.getPublic());

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build());

        assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testProofOfPossessionWithoutSender()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setPKMACValueGeneration(new PKMACValueGenerator(new JcaPKMACValuesCalculator()), "fred".toCharArray())
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build());

        // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.verifySigningKeyPOP(new JcaContentVerifierBuilder().setProvider(BC).build(kp.getPublic()));
            fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }

        assertTrue(certReqMsg.verifySigningKeyPOP(new JcaContentVerifierBuilder().setProvider(BC).build(kp.getPublic()), new PKMACValueVerifier(new JcaPKMACValuesCalculator().setProvider(BC)), "fred".toCharArray())); 

        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testProofOfPossessionWithSender()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setPublicKey(kp.getPublic())
                    .setSender(new X500Principal("CN=Test"))
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build());

        // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.verifySigningKeyPOP(new JcaContentVerifierBuilder().setProvider(BC).build(kp.getPublic()), new PKMACValueVerifier(new JcaPKMACValuesCalculator().setProvider(BC)), "fred".toCharArray());

            fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }


        assertTrue(certReqMsg.verifySigningKeyPOP(new JcaContentVerifierBuilder().setProvider(BC).build(kp.getPublic())));

        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    private static X509Certificate makeV1Certificate(KeyPair subKP, String _subDN, KeyPair issKP, String _issDN)
        throws GeneralSecurityException, IOException
    {

        PublicKey subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();

        X509V1CertificateGenerator v1CertGen = new X509V1CertificateGenerator();

        v1CertGen.reset();
        v1CertGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        v1CertGen.setIssuerDN(new X509Name(_issDN));
        v1CertGen.setNotBefore(new Date(System.currentTimeMillis()));
        v1CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)));
        v1CertGen.setSubjectDN(new X509Name(_subDN));
        v1CertGen.setPublicKey(subPub);

        if (issPub instanceof RSAPublicKey)
        {
            v1CertGen.setSignatureAlgorithm("SHA1WithRSA");
        }
        else if (issPub.getAlgorithm().equals("DSA"))
        {
            v1CertGen.setSignatureAlgorithm("SHA1withDSA");
        }
        else if (issPub.getAlgorithm().equals("ECDSA"))
        {
            v1CertGen.setSignatureAlgorithm("SHA1withECDSA");
        }
        else if (issPub.getAlgorithm().equals("ECGOST3410"))
        {
            v1CertGen.setSignatureAlgorithm("GOST3411withECGOST3410");
        }
        else
        {
            v1CertGen.setSignatureAlgorithm("GOST3411WithGOST3410");
        }

        X509Certificate _cert = v1CertGen.generate(issPriv);

        _cert.checkValidity(new Date());
        _cert.verify(issPub);

        return _cert;
    }
}