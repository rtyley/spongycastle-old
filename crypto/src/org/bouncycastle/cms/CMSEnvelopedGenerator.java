package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientEncryptedKey;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.PrincipalUtil;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

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

    private static final CMSEnvelopedHelper HELPER = CMSEnvelopedHelper.INSTANCE;

    List recipientInfs = new ArrayList();
    SecureRandom rand = new SecureRandom();

    protected class RecipientInf
    {
        X509Certificate cert;
        AlgorithmIdentifier keyEncAlg;
        PublicKey pubKey;
        ASN1OctetString subKeyId;

        SecretKey secKey;
        KEKIdentifier secKeyId;

        OriginatorIdentifierOrKey originator;
        ASN1OctetString           ukm;

        AlgorithmIdentifier       derivationAlg;

        RecipientInf(
            X509Certificate cert)
        {
            this.cert = cert;
            this.pubKey = cert.getPublicKey();

            try
            {
                TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(
                                                       ASN1Object.fromByteArray(cert.getTBSCertificate()));
                SubjectPublicKeyInfo info = tbs.getSubjectPublicKeyInfo();

                keyEncAlg = info.getAlgorithmId();
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("can't extract key algorithm from this cert");
            }
            catch (CertificateEncodingException e)
            {
                throw new IllegalArgumentException("can't extract tbs structure from this cert");
            }
        }

        RecipientInf(
            PublicKey               pubKey,
            ASN1OctetString         subKeyId)
        {
            this.pubKey = pubKey;
            this.subKeyId = subKeyId;

            try
            {
                SubjectPublicKeyInfo    info = SubjectPublicKeyInfo.getInstance(
                                                        ASN1Object.fromByteArray(pubKey.getEncoded()));

                keyEncAlg = info.getAlgorithmId();
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("can't extract key algorithm from this key");
            }
        }

        RecipientInf(
            SecretKey               secKey,
            KEKIdentifier           secKeyId)
        {
            this.secKey = secKey;
            this.secKeyId = secKeyId;

            if (secKey.getAlgorithm().startsWith("DES"))
            {
                keyEncAlg = new AlgorithmIdentifier(
                        new DERObjectIdentifier("1.2.840.113549.1.9.16.3.6"),
                            new DERNull());
            }
            else if (secKey.getAlgorithm().startsWith("RC2"))
            {
                keyEncAlg = new AlgorithmIdentifier(
                        new DERObjectIdentifier("1.2.840.113549.1.9.16.3.7"),
                        new DERInteger(58));
            }
            else if (secKey.getAlgorithm().startsWith("AES"))
            {
                int length = secKey.getEncoded().length * 8;
                DERObjectIdentifier wrapOid;

                if (length == 128)
                {
                    wrapOid = NISTObjectIdentifiers.id_aes128_wrap;
                }
                else if (length == 192)
                {
                    wrapOid = NISTObjectIdentifiers.id_aes192_wrap;
                }
                else if (length == 256)
                {
                    wrapOid = NISTObjectIdentifiers.id_aes256_wrap;
                }
                else
                {
                    throw new IllegalArgumentException("illegal keysize in AES");
                }

                keyEncAlg = new AlgorithmIdentifier(wrapOid);  // parameters absent
            }
            else if (secKey.getAlgorithm().startsWith("SEED"))
            {
                // parameters absent
                keyEncAlg = new AlgorithmIdentifier(KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
            }
            else if (secKey.getAlgorithm().startsWith("Camellia"))
            {
                int length = secKey.getEncoded().length * 8;
                DERObjectIdentifier wrapOid;

                if (length == 128)
                {
                    wrapOid = NTTObjectIdentifiers.id_camellia128_wrap;
                }
                else if (length == 192)
                {
                    wrapOid = NTTObjectIdentifiers.id_camellia192_wrap;
                }
                else if (length == 256)
                {
                    wrapOid = NTTObjectIdentifiers.id_camellia256_wrap;
                }
                else
                {
                    throw new IllegalArgumentException("illegal keysize in Camellia");
                }

                keyEncAlg = new AlgorithmIdentifier(wrapOid);  // parameters must be absent
            }
            else
            {
                throw new IllegalArgumentException("unknown algorithm");
            }
        }

        public RecipientInf(SecretKey secretKey, String algorithm, String wrapOid, OriginatorIdentifierOrKey originator, X509Certificate cert)
        {
            ASN1EncodableVector params = new ASN1EncodableVector();

            params.add(new DERObjectIdentifier(wrapOid));
            params.add(DERNull.INSTANCE);

            this.secKey = secretKey;
            this.keyEncAlg = new AlgorithmIdentifier(new DERObjectIdentifier(algorithm), new DERSequence(params));
            this.originator = originator;
            this.cert = cert;
        }

        public RecipientInf(SecretKey secretKey, AlgorithmIdentifier derivationAlg)
        {
            this.secKey = secretKey;
            this.derivationAlg = derivationAlg;
        }

        RecipientInfo toRecipientInfo(
            SecretKey           key,
            String              prov)
            throws IOException, GeneralSecurityException
        {
            if (pubKey != null)
            {
                ASN1OctetString         encKey;

                Cipher keyCipher = HELPER.createAsymmetricCipher(keyEncAlg.getObjectId().getId(), prov);
                try
                {
                    keyCipher.init(Cipher.WRAP_MODE, pubKey);

                    encKey = new DEROctetString(keyCipher.wrap(key));
                }
                catch (GeneralSecurityException e)   // some providers do not support wrap
                {
                    keyCipher.init(Cipher.ENCRYPT_MODE, pubKey);

                    encKey = new DEROctetString(keyCipher.doFinal(key.getEncoded()));
                }
                catch (IllegalStateException e)   // some providers do not support wrap
                {
                    keyCipher.init(Cipher.ENCRYPT_MODE, pubKey);

                    encKey = new DEROctetString(keyCipher.doFinal(key.getEncoded()));
                }
                catch (UnsupportedOperationException e)   // some providers do not support UNWRAP
                {
                    keyCipher.init(Cipher.ENCRYPT_MODE, key);

                    encKey = new DEROctetString(keyCipher.doFinal(key.getEncoded()));
                }

                if (cert != null)
                {
                    ASN1InputStream aIn = new ASN1InputStream(cert.getTBSCertificate());
                    TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(aIn.readObject());
                    IssuerAndSerialNumber encSid = new IssuerAndSerialNumber(tbs.getIssuer(), tbs.getSerialNumber().getValue());

                    return new RecipientInfo(new KeyTransRecipientInfo(
                            new RecipientIdentifier(encSid),
                            keyEncAlg,
                            encKey));
                }
                else
                {
                    return new RecipientInfo(new KeyTransRecipientInfo(
                            new RecipientIdentifier(subKeyId),
                            keyEncAlg,
                            encKey));
                }
            }
            else if (originator != null)
            {
                Cipher              keyCipher = HELPER.createAsymmetricCipher(
                                                      DERObjectIdentifier.getInstance(ASN1Sequence.getInstance(keyEncAlg.getParameters()).getObjectAt(0)).getId(), prov);

                keyCipher.init(Cipher.WRAP_MODE, secKey);

                ASN1OctetString         encKey = new DEROctetString(
                                                        keyCipher.wrap(key));

                RecipientEncryptedKey rKey = new RecipientEncryptedKey(new KeyAgreeRecipientIdentifier(
                                                                            new IssuerAndSerialNumber(PrincipalUtil.getIssuerX509Principal(cert), cert.getSerialNumber())),
                                                 encKey);

                return new RecipientInfo(new KeyAgreeRecipientInfo(originator, ukm, keyEncAlg, new DERSequence(rKey)));
            }
            else if (derivationAlg != null)
            {
                Cipher              keyCipher = HELPER.createAsymmetricCipher(
                                                                  HELPER.getRFC3211WrapperName(secKey.getAlgorithm()), prov);

                keyCipher.init(Cipher.WRAP_MODE, secKey);

                ASN1OctetString         encKey = new DEROctetString(keyCipher.wrap(key));

                ASN1EncodableVector     v = new ASN1EncodableVector();

                v.add(new DERObjectIdentifier(secKey.getAlgorithm()));
                v.add(new DEROctetString(keyCipher.getIV()));

                keyEncAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_alg_PWRI_KEK, new DERSequence(v));

                return new RecipientInfo(new PasswordRecipientInfo(derivationAlg, keyEncAlg, encKey));
            }
            else
            {
                Cipher              keyCipher = HELPER.createAsymmetricCipher(
                                                               keyEncAlg.getObjectId().getId(), prov);

                keyCipher.init(Cipher.WRAP_MODE, secKey);

                ASN1OctetString         encKey = new DEROctetString(keyCipher.wrap(key));

                return new RecipientInfo(new KEKRecipientInfo(secKeyId, keyEncAlg, encKey));
            }
        }
    }

    /**
     * base constructor
     */
    public CMSEnvelopedGenerator()
    {
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
        recipientInfs.add(new RecipientInf(cert));
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
        recipientInfs.add(new CMSEnvelopedGenerator.RecipientInf(key, new DEROctetString(subKeyId)));
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
        recipientInfs.add(new RecipientInf(key, new KEKIdentifier(
                                                keyIdentifier, null, null)));
    }

    public void addPasswordRecipient(
        CMSPBEKey pbeKey,
        String    kekAlgorithmOid)
    {
        PBKDF2Params params = new PBKDF2Params(pbeKey.getSalt(), pbeKey.getIterationCount());

        recipientInfs.add(new RecipientInf(new SecretKeySpec(pbeKey.getEncoded(kekAlgorithmOid), kekAlgorithmOid), new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, params)));
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
        KeyAgreement agreement = KeyAgreement.getInstance(agreementAlgorithm, provider);

        agreement.init(senderPrivateKey);

        agreement.doPhase(recipientCert.getPublicKey(), true);

        try
        {
            SubjectPublicKeyInfo oPubKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray(senderPublicKey.getEncoded()));
            OriginatorIdentifierOrKey originator = new OriginatorIdentifierOrKey(
                                                       new OriginatorPublicKey(
                                                            new AlgorithmIdentifier(oPubKeyInfo.getAlgorithmId().getObjectId(), new DERNull()),
                                                            oPubKeyInfo.getPublicKeyData().getBytes()));

            recipientInfs.add(new RecipientInf(agreement.generateSecret(cekWrapAlgorithm), agreementAlgorithm, cekWrapAlgorithm, originator, recipientCert));
        }
        catch (IOException e)
        {
            throw new InvalidKeyException("cannot extract originator public key: " + e);
        }
    }
}
