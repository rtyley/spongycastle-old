package org.bouncycastle.cms;

import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.ecc.MQVuserKeyingMaterial;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.MQVPrivateKeySpec;
import org.bouncycastle.jce.spec.MQVPublicKeySpec;

/**
 * General class for generating a CMS enveloped-data message.
 *
 * A simple example of usage.
 *
 * <pre>
 *      CMSEnvelopedDataGenerator  fact = new CMSEnvelopedDataGenerator();
 *
 *      fact.addKeyTransRecipient(cert);
 *
 *      CMSEnvelopedData         data = fact.generate(content, algorithm, "BC");
 * </pre>
 */
public class CMSEnvelopedGenerator
{
    public static final String  DES_EDE3_CBC    = PKCSObjectIdentifiers.des_EDE3_CBC.getId();
    public static final String  RC2_CBC         = PKCSObjectIdentifiers.RC2_CBC.getId();
    public static final String  IDEA_CBC        = "1.3.6.1.4.1.188.7.1.1.2";
    public static final String  CAST5_CBC       = "1.2.840.113533.7.66.10";
    public static final String  AES128_CBC      = NISTObjectIdentifiers.id_aes128_CBC.getId();
    public static final String  AES192_CBC      = NISTObjectIdentifiers.id_aes192_CBC.getId();
    public static final String  AES256_CBC      = NISTObjectIdentifiers.id_aes256_CBC.getId();
    public static final String  CAMELLIA128_CBC = NTTObjectIdentifiers.id_camellia128_cbc.getId();
    public static final String  CAMELLIA192_CBC = NTTObjectIdentifiers.id_camellia192_cbc.getId();
    public static final String  CAMELLIA256_CBC = NTTObjectIdentifiers.id_camellia256_cbc.getId();
    public static final String  SEED_CBC        = KISAObjectIdentifiers.id_seedCBC.getId();

    public static final String  DES_EDE3_WRAP   = PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId();
    public static final String  AES128_WRAP     = NISTObjectIdentifiers.id_aes128_wrap.getId();
    public static final String  AES192_WRAP     = NISTObjectIdentifiers.id_aes192_wrap.getId();
    public static final String  AES256_WRAP     = NISTObjectIdentifiers.id_aes256_wrap.getId();
    public static final String  CAMELLIA128_WRAP = NTTObjectIdentifiers.id_camellia128_wrap.getId();
    public static final String  CAMELLIA192_WRAP = NTTObjectIdentifiers.id_camellia192_wrap.getId();
    public static final String  CAMELLIA256_WRAP = NTTObjectIdentifiers.id_camellia256_wrap.getId();
    public static final String  SEED_WRAP       = KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap.getId();

    public static final String  ECDH_SHA1KDF    = X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId();
    public static final String  ECMQV_SHA1KDF   = X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme.getId();

    final List recipientInfoGenerators = new ArrayList();
    final SecureRandom rand;

    /**
     * base constructor
     */
    public CMSEnvelopedGenerator()
    {
        this(new SecureRandom());
    }

    /**
     * constructor allowing specific source of randomness
     * @param rand instance of SecureRandom to use
     */
    public CMSEnvelopedGenerator(
        SecureRandom rand)
    {
        this.rand = rand;
    }

    /**
     * add a recipient.
     *
     * @param cert recipient's public key certificate
     * @exception IllegalArgumentException if there is a problem with the certificate
     */
    public void addKeyTransRecipient(
        X509Certificate cert)
        throws IllegalArgumentException
    {
        KeyTransRecipientInfoGenerator ktrig = new KeyTransRecipientInfoGenerator();
        ktrig.setRecipientCert(cert);

        recipientInfoGenerators.add(ktrig);
    }

    /**
     * add a recipient
     *
     * @param key the public key used by the recipient
     * @param subKeyId the identifier for the recipient's public key
     * @exception IllegalArgumentException if there is a problem with the key
     */
    public void addKeyTransRecipient(
        PublicKey   key,
        byte[]      subKeyId)
        throws IllegalArgumentException
    {
        KeyTransRecipientInfoGenerator ktrig = new KeyTransRecipientInfoGenerator();
        ktrig.setRecipientPublicKey(key);
        ktrig.setSubjectKeyIdentifier(new DEROctetString(subKeyId));

        recipientInfoGenerators.add(ktrig);
    }

    /**
     * add a KEK recipient.
     * @param key the secret key to use for wrapping
     * @param keyIdentifier the byte string that identifies the key
     */
    public void addKEKRecipient(
        SecretKey   key,
        byte[]      keyIdentifier)
    {
        KEKRecipientInfoGenerator kekrig = new KEKRecipientInfoGenerator();
        kekrig.setKEKIdentifier(new KEKIdentifier(keyIdentifier, null, null));
        kekrig.setWrapKey(key);

        recipientInfoGenerators.add(kekrig);
    }

    public void addPasswordRecipient(
        CMSPBEKey pbeKey,
        String    kekAlgorithmOid)
    {
        PBKDF2Params params = new PBKDF2Params(pbeKey.getSalt(), pbeKey.getIterationCount());

        PasswordRecipientInfoGenerator prig = new PasswordRecipientInfoGenerator(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, iterationCount)));
        prig.setDerivationAlg(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, params));
        prig.setWrapKey(new SecretKeySpec(pbeKey.getEncoded(kekAlgorithmOid), kekAlgorithmOid));

        recipientInfoGenerators.add(prig);
    }

    /**
     * Add a key agreement based recipient.
     *
     * @param agreementAlgorithm key agreement algorithm to use.
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCert recipient's public key certificate.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     * @exception NoSuchProviderException if the specified provider cannot be found
     * @exception NoSuchAlgorithmException if the algorithm requested cannot be found
     * @exception InvalidKeyException if the keys are inappropriate for the algorithm specified
     */
    public void addKeyAgreementRecipient(
        String           agreementAlgorithm,
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        X509Certificate  recipientCert,
        String           cekWrapAlgorithm,
        String           provider)
        throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException
    {
        addKeyAgreementRecipient(agreementAlgorithm, senderPrivateKey, senderPublicKey, recipientCert,  cekWrapAlgorithm, CMSUtils.getProvider(provider));
    }

    /**
     * Add a key agreement based recipient.
     *
     * @param agreementAlgorithm key agreement algorithm to use.
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCert recipient's public key certificate.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     * @exception NoSuchAlgorithmException if the algorithm requested cannot be found
     * @exception InvalidKeyException if the keys are inappropriate for the algorithm specified
     */
    public void addKeyAgreementRecipient(
        String           agreementAlgorithm,
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        X509Certificate  recipientCert,
        String           cekWrapAlgorithm,
        Provider         provider)
        throws NoSuchAlgorithmException, InvalidKeyException
    {
        OriginatorIdentifierOrKey originator;
        try
        {
            originator = new OriginatorIdentifierOrKey(
                    createOriginatorPublicKey(senderPublicKey));
        }
        catch (IOException e)
        {
            throw new InvalidKeyException("cannot extract originator public key: " + e);
        }

        ASN1OctetString ukm = null;
        PublicKey recipientPublicKey = recipientCert.getPublicKey();

        if (agreementAlgorithm.equals(CMSEnvelopedGenerator.ECMQV_SHA1KDF))
        {
            try
            {
                ECParameterSpec ecParamSpec = ((ECPublicKey)senderPublicKey).getParams();

                KeyPairGenerator ephemKPG = KeyPairGenerator.getInstance(agreementAlgorithm, provider.getName());
                ephemKPG.initialize(ecParamSpec, rand);

                KeyPair ephemKP = ephemKPG.generateKeyPair();

                ukm = new DEROctetString(
                    new MQVuserKeyingMaterial(
                        createOriginatorPublicKey(ephemKP.getPublic()), null));

                recipientPublicKey = new MQVPublicKeySpec(recipientPublicKey, recipientPublicKey);
                senderPrivateKey = new MQVPrivateKeySpec(
                    senderPrivateKey, ephemKP.getPrivate(), ephemKP.getPublic());
            }
            catch (InvalidAlgorithmParameterException e)
            {
                throw new InvalidKeyException("cannot determine MQV ephemeral key pair parameters from public key: " + e);
            }
            catch (NoSuchProviderException e)
            {
                throw new InvalidKeyException("cannot extract MQV ephemeral public key: " + e);
            }
            catch (IOException e)
            {
                throw new InvalidKeyException("cannot extract MQV ephemeral public key: " + e);
            }
        }

        KeyAgreement agreement = KeyAgreement.getInstance(agreementAlgorithm, provider);
        agreement.init(senderPrivateKey, rand);
        agreement.doPhase(recipientPublicKey, true);
        SecretKey wrapKey = agreement.generateSecret(cekWrapAlgorithm);

        KeyAgreeRecipientInfoGenerator karig = new KeyAgreeRecipientInfoGenerator();
        karig.setAlgorithmOID(new DERObjectIdentifier(agreementAlgorithm));
        karig.setOriginator(originator);
        karig.setRecipientCert(recipientCert);
        karig.setUKM(ukm);
        karig.setWrapKey(wrapKey);
        karig.setWrapAlgorithmOID(new DERObjectIdentifier(cekWrapAlgorithm));

        recipientInfoGenerators.add(karig);
    }

    protected AlgorithmIdentifier getAlgorithmIdentifier(String encryptionOID, AlgorithmParameters params) throws IOException
    {
        DEREncodable asn1Params;
        if (params != null)
        {
            asn1Params = ASN1Object.fromByteArray(params.getEncoded("ASN.1"));
        }
        else
        {
            asn1Params = DERNull.INSTANCE;
        }

        return new AlgorithmIdentifier(
            new DERObjectIdentifier(encryptionOID),
            asn1Params);
    }

    protected AlgorithmParameters generateParameters(String encryptionOID, SecretKey encKey, Provider encProvider)
        throws CMSException
    {
        try
        {
            AlgorithmParameterGenerator pGen = AlgorithmParameterGenerator.getInstance(encryptionOID, encProvider.getName());

            if (encryptionOID.equals(RC2_CBC))
            {
                byte[]  iv = new byte[8];

                rand.nextBytes(iv);

                try
                {
                    pGen.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, iv), rand);
                }
                catch (InvalidAlgorithmParameterException e)
                {
                    throw new CMSException("parameters generation error: " + e, e);
                }
            }

            return pGen.generateParameters();
        }
        catch (NoSuchProviderException e)
        {
            return null;
        }
        catch (NoSuchAlgorithmException e)
        {
            return null;
        }
    }

    private static OriginatorPublicKey createOriginatorPublicKey(PublicKey publicKey)
        throws IOException
    {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(
            ASN1Object.fromByteArray(publicKey.getEncoded()));
        return new OriginatorPublicKey(
            new AlgorithmIdentifier(spki.getAlgorithmId().getObjectId(), DERNull.INSTANCE),
            spki.getPublicKeyData().getBytes());
    }
}
