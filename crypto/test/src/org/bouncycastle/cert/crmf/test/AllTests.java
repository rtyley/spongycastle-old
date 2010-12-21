package org.bouncycastle.cert.crmf.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.EncKeyWithID;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.EncryptedValueBuilder;
import org.bouncycastle.cert.crmf.EncryptedValuePadder;
import org.bouncycastle.cert.crmf.EncryptedValueParser;
import org.bouncycastle.cert.crmf.FixedLengthMGF1Padder;
import org.bouncycastle.cert.crmf.PKIArchiveControl;
import org.bouncycastle.cert.crmf.PKMACBuilder;
import org.bouncycastle.cert.crmf.ValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessage;
import org.bouncycastle.cert.crmf.jcajce.JcaCertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaEncryptedValueBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcaPKIArchiveControlBuilder;
import org.bouncycastle.cert.crmf.jcajce.JceAsymmetricValueDecryptorGenerator;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.cert.crmf.jcajce.JcePKMACValuesCalculator;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.x509.X509V1CertificateGenerator;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String PASSPHRASE = "hello world";

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

    public void testBasicMessageWithArchiveControl()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaCertificateRequestMessageBuilder certReqBuild = new JcaCertificateRequestMessageBuilder(BigInteger.ONE);

        certReqBuild.setSubject(new X500Principal("CN=Test"))
                    .setPublicKey(kp.getPublic());

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=Test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build());

        assertEquals(new X500Principal("CN=Test"), certReqMsg.getSubjectX500Principal());
        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());

        PKIArchiveControl archiveControl = (PKIArchiveControl)certReqMsg.getControl(CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions);

        assertEquals(PKIArchiveControl.encryptedPrivKey, archiveControl.getArchiveType());

        assertTrue(archiveControl.isEnvelopedData());

        RecipientInformationStore recips = archiveControl.getEnvelopedData().getRecipientInfos();

        RecipientId recipientId = new RecipientId();

        recipientId.setIssuer(cert.getIssuerX500Principal().getEncoded());
        recipientId.setSerialNumber(cert.getSerialNumber());

        RecipientInformation recipientInformation = recips.get(recipientId);

        assertNotNull(recipientInformation);

        EncKeyWithID encKeyWithID = EncKeyWithID.getInstance(recipientInformation.getContent(new JceKeyTransEnvelopedRecipient(kp.getPrivate()).setProvider(BC)));

        assertTrue(encKeyWithID.hasIdentifier());
        assertFalse(encKeyWithID.isIdentifierUTF8String());

        assertEquals(new GeneralName(X509Name.getInstance(new X500Principal("CN=Test").getEncoded())), encKeyWithID.getIdentifier());
        assertTrue(Arrays.areEqual(kp.getPrivate().getEncoded(), encKeyWithID.getPrivateKey().getEncoded()));
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
                    .setAuthInfoPKMAC(new PKMACBuilder(new JcePKMACValuesCalculator()), "fred".toCharArray())
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build());

        // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()));
            fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }

        assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()), new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "fred".toCharArray()));

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
                    .setAuthInfoSender(new X500Principal("CN=Test"))
                    .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA1withRSA").setProvider(BC).build(kp.getPrivate()));

        certReqBuild.addControl(new JcaPKIArchiveControlBuilder(kp.getPrivate(), new X500Principal("CN=test"))
                                      .addRecipientGenerator(new JceKeyTransRecipientInfoGenerator(cert).setProvider(BC))
                                      .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES128_CBC)).setProvider(BC).build()));

        JcaCertificateRequestMessage certReqMsg = new JcaCertificateRequestMessage(certReqBuild.build());

        // check that internal check on popo signing is working okay
        try
        {
            certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic()), new PKMACBuilder(new JcePKMACValuesCalculator().setProvider(BC)), "fred".toCharArray());

            fail("IllegalStateException not thrown");
        }
        catch (IllegalStateException e)
        {
            // ignore
        }


        assertTrue(certReqMsg.isValidSigningKeyPOP(new JcaContentVerifierProviderBuilder().setProvider(BC).build(kp.getPublic())));

        assertEquals(kp.getPublic(), certReqMsg.getPublicKey());
    }

    public void testEncryptedValue()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        JcaEncryptedValueBuilder build = new JcaEncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());
        EncryptedValue value = build.build(cert);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValueParserTest(value, decGen, cert);

        // try indirect
        encryptedValueParserTest(EncryptedValue.getInstance(value.getEncoded()), decGen, cert);
    }

    private void encryptedValueParserTest(EncryptedValue value, ValueDecryptorGenerator decGen, X509Certificate cert)
        throws Exception
    {
        EncryptedValueParser  parser = new EncryptedValueParser(value);

        X509CertificateHolder holder = parser.readCertificateHolder(decGen);

        assertTrue(Arrays.areEqual(cert.getEncoded(), holder.getEncoded()));
    }

    public void testEncryptedValuePassphrase()
        throws Exception
    {
        char[] passphrase = PASSPHRASE.toCharArray();
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        EncryptedValueBuilder build = new EncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build());
        EncryptedValue value = build.build(passphrase);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValuePassphraseParserTest(value, null, decGen, cert);

        // try indirect
        encryptedValuePassphraseParserTest(EncryptedValue.getInstance(value.getEncoded()), null, decGen, cert);
    }

    public void testEncryptedValuePassphraseWithPadding()
        throws Exception
    {
        char[] passphrase = PASSPHRASE.toCharArray();
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(512);

        KeyPair kp = kGen.generateKeyPair();
        X509Certificate cert = makeV1Certificate(kp, "CN=Test", kp, "CN=Test");

        FixedLengthMGF1Padder mgf1Padder = new FixedLengthMGF1Padder(200, new SecureRandom());
        EncryptedValueBuilder build = new EncryptedValueBuilder(new JceAsymmetricKeyWrapper(cert.getPublicKey()).setProvider(BC), new JceCRMFEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider(BC).build(), mgf1Padder);
        EncryptedValue value = build.build(passphrase);
        ValueDecryptorGenerator decGen = new JceAsymmetricValueDecryptorGenerator(kp.getPrivate()).setProvider(BC);

        // try direct
        encryptedValuePassphraseParserTest(value, mgf1Padder, decGen, cert);

        // try indirect
        encryptedValuePassphraseParserTest(EncryptedValue.getInstance(value.getEncoded()), mgf1Padder, decGen, cert);
    }

    private void encryptedValuePassphraseParserTest(EncryptedValue value, EncryptedValuePadder padder, ValueDecryptorGenerator decGen, X509Certificate cert)
        throws Exception
    {
        EncryptedValueParser  parser = new EncryptedValueParser(value, padder);

        assertTrue(Arrays.areEqual(PASSPHRASE.toCharArray(), parser.readPassphrase(decGen)));
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