package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERConstructedOctetString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
import org.bouncycastle.asn1.cms.OriginatorPublicKey;
import org.bouncycastle.asn1.cms.RecipientEncryptedKey;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.PrincipalUtil;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.RC2ParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
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
public class CMSEnvelopedDataGenerator
{
    public static final String  DES_EDE3_CBC    = PKCSObjectIdentifiers.des_EDE3_CBC.getId();
    public static final String  RC2_CBC         = PKCSObjectIdentifiers.RC2_CBC.getId();
    public static final String  IDEA_CBC        = "1.3.6.1.4.1.188.7.1.1.2";
    public static final String  CAST5_CBC       = "1.2.840.113533.7.66.10";
    public static final String  AES128_CBC      = NISTObjectIdentifiers.id_aes128_CBC.getId(); 
    public static final String  AES192_CBC      = NISTObjectIdentifiers.id_aes192_CBC.getId(); 
    public static final String  AES256_CBC      = NISTObjectIdentifiers.id_aes256_CBC.getId();

    public static final String  DES_EDE3_WRAP   = PKCSObjectIdentifiers.id_alg_CMS3DESwrap.getId();
    public static final String  AES128_WRAP     = NISTObjectIdentifiers.id_aes128_wrap.getId();
    public static final String  AES256_WRAP     = NISTObjectIdentifiers.id_aes256_wrap.getId();

    List          recipientInfs = new ArrayList();
    SecureRandom  rand = new SecureRandom();

    private class RecipientInf
    {
        X509Certificate         cert;
        AlgorithmIdentifier     keyEncAlg;
        PublicKey               pubKey;
        ASN1OctetString         subKeyId;

        SecretKey               secKey;
        KEKIdentifier           secKeyId;

        OriginatorIdentifierOrKey originator;
        ASN1OctetString           ukm;

        RecipientInf(
            X509Certificate cert)
        {
            this.cert = cert;
            this.pubKey = cert.getPublicKey();

            try
            {
                TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(
                                                       ASN1Object.fromByteArray(cert.getTBSCertificate()));
                SubjectPublicKeyInfo    info = tbs.getSubjectPublicKeyInfo();

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
                
                keyEncAlg = new AlgorithmIdentifier(wrapOid, new DERNull());
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

        RecipientInfo toRecipientInfo(
            SecretKey           key,
            String              prov)
            throws IOException, GeneralSecurityException
        {
            if (pubKey != null)
            {
                ASN1OctetString         encKey;

                Cipher              keyCipher = CMSEnvelopedHelper.INSTANCE.createAsymmetricCipher(
                                                                   keyEncAlg.getObjectId().getId(), prov);
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
                
                if (cert != null)
                {
                    ASN1InputStream         aIn = new ASN1InputStream(cert.getTBSCertificate());
                    TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(aIn.readObject());
                    IssuerAndSerialNumber   encSid = new IssuerAndSerialNumber(tbs.getIssuer(), tbs.getSerialNumber().getValue());


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
            else
            {
                if (originator != null)
                {
                    Cipher              keyCipher = CMSEnvelopedHelper.INSTANCE.createAsymmetricCipher(
                                                          DERObjectIdentifier.getInstance(ASN1Sequence.getInstance(keyEncAlg.getParameters()).getObjectAt(0)).getId(), prov);

                    keyCipher.init(Cipher.WRAP_MODE, secKey);

                    ASN1OctetString         encKey = new DEROctetString(
                                                            keyCipher.wrap(key));

                    RecipientEncryptedKey rKey = new RecipientEncryptedKey(new KeyAgreeRecipientIdentifier(
                                                                                new IssuerAndSerialNumber(PrincipalUtil.getIssuerX509Principal(cert), cert.getSerialNumber())),
                                                     encKey);

                    return new RecipientInfo(new KeyAgreeRecipientInfo(originator, ukm, keyEncAlg, new DERSequence(rKey)));
                }
                else
                {
                    Cipher              keyCipher = CMSEnvelopedHelper.INSTANCE.createAsymmetricCipher(
                                                                   keyEncAlg.getObjectId().getId(), prov);

                    keyCipher.init(Cipher.WRAP_MODE, secKey);

                    ASN1OctetString         encKey = new DEROctetString(
                                                            keyCipher.wrap(key));

                    return new RecipientInfo(new KEKRecipientInfo(
                                                    secKeyId, keyEncAlg, encKey));
                }
            }
        }
    }

    /**
     * base constructor
     */
    public CMSEnvelopedDataGenerator()
    {
    }

    /**
     * add a recipient.
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
     */
    public void addKeyTransRecipient(
        PublicKey   key,
        byte[]      subKeyId)
        throws IllegalArgumentException
    {
        recipientInfs.add(new RecipientInf(key, new DEROctetString(subKeyId)));
    }

    /**
     * add a KEK recipient.
     */
    public void addKEKRecipient(
        SecretKey   key,
        byte[]      keyIdentifier)
    {
        recipientInfs.add(new RecipientInf(key, new KEKIdentifier(
                                                keyIdentifier, null, null)));
    }

    /**
     * Add a key agreement based recipient.
     * 
     * @param senderPrivateKey private key to initialise sender side of agreement with.
     * @param senderPublicKey sender public key to include with message.
     * @param recipientCert recipient's public key certificate.
     * @param cekWrapAlgorithm OID for key wrapping algorithm to use.
     * @param provider provider to use for the agreement calculation.
     */
    public void addKeyAgreementRecipient(
        PrivateKey       senderPrivateKey,
        PublicKey        senderPublicKey,
        X509Certificate  recipientCert,
        String           cekWrapAlgorithm,
        String           provider)
        throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException
    {
        String algorithm;

        if (senderPrivateKey instanceof DHKey)
        {
            algorithm = null;
        }
        else if (senderPrivateKey.getAlgorithm().startsWith("EC"))
        {
            // TODO - need to check for GOST, ECDHC
            algorithm = X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme.getId();
        }
        else
        {
            throw new InvalidKeyException("can't match private key with an algorithm");
        }

        KeyAgreement agreement = KeyAgreement.getInstance(algorithm, provider);

        agreement.init(senderPrivateKey);

        agreement.doPhase(recipientCert.getPublicKey(), true);

        try
        {
            SubjectPublicKeyInfo oPubKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Object.fromByteArray(senderPublicKey.getEncoded()));
            OriginatorIdentifierOrKey originator = new OriginatorIdentifierOrKey(
                                                       new OriginatorPublicKey(
                                                            new AlgorithmIdentifier(oPubKeyInfo.getAlgorithmId().getObjectId(), new DERNull()),
                                                            oPubKeyInfo.getPublicKeyData().getBytes()));

            recipientInfs.add(new RecipientInf(agreement.generateSecret(cekWrapAlgorithm), algorithm, cekWrapAlgorithm, originator, recipientCert));
        }
        catch (IOException e)
        {
            throw new InvalidKeyException("cannot extract originator public key: " + e);
        }
    }
    
    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider and the passed in key generator.
     */
    private CMSEnvelopedData generate(
        CMSProcessable  content,
        String          encryptionOID,
        KeyGenerator    keyGen,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        String                  encProviderName = keyGen.getProvider().getName();
        ASN1EncodableVector     recipientInfos = new ASN1EncodableVector();
        AlgorithmIdentifier     encAlgId;
        SecretKey               encKey;
        ASN1OctetString         encContent;

        try
        {
            Cipher              cipher = Cipher.getInstance(encryptionOID, encProviderName);

            AlgorithmParameters params;
            DEREncodable        asn1Params;
            
            encKey = keyGen.generateKey();

            try
            {
                AlgorithmParameterGenerator pGen = AlgorithmParameterGenerator.getInstance(encryptionOID, encProviderName);

                if (encryptionOID.equals(RC2_CBC))
                {
                    byte[]  iv = new byte[8];

                    //
                    // mix in a bit extra...
                    //
                    rand.setSeed(System.currentTimeMillis());

                    rand.nextBytes(iv);

                    pGen.init(new RC2ParameterSpec(encKey.getEncoded().length * 8, iv));
                }
                
                params = pGen.generateParameters();

                ASN1InputStream             aIn = new ASN1InputStream(params.getEncoded("ASN.1"));

                asn1Params = aIn.readObject();
            }
            catch (NoSuchAlgorithmException e)
            {
                params = null;
                asn1Params = new DERNull();
            }

            encAlgId = new AlgorithmIdentifier(
                                new DERObjectIdentifier(encryptionOID),
                                asn1Params);

            cipher.init(Cipher.ENCRYPT_MODE, encKey, params);

            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            CipherOutputStream      cOut = new CipherOutputStream(bOut, cipher);

            content.write(cOut);

            cOut.close();

            encContent = new BERConstructedOctetString(bOut.toByteArray());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new CMSException("algorithm parameters invalid.", e);
        }
        catch (IOException e)
        {
            throw new CMSException("exception decoding algorithm parameters.", e);
        }

        Iterator            it = recipientInfs.iterator();

        while (it.hasNext())
        {
            RecipientInf            recipient = (RecipientInf)it.next();

            try
            {
                recipientInfos.add(recipient.toRecipientInfo(encKey, provider));
            }
            catch (IOException e)
            {
                throw new CMSException("encoding error.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CMSException("key inappropriate for algorithm.", e);
            }
            catch (GeneralSecurityException e)
            {
                throw new CMSException("error making encrypted content.", e);
            }
        }

        EncryptedContentInfo  eci = new EncryptedContentInfo(
                                 PKCSObjectIdentifiers.data,
                                 encAlgId, 
                                 encContent);

        ContentInfo contentInfo = new ContentInfo(
                PKCSObjectIdentifiers.envelopedData,
                new EnvelopedData(null, new DERSet(recipientInfos), eci, null));

        return new CMSEnvelopedData(contentInfo);
    }
    
    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     */
    public CMSEnvelopedData generate(
        CMSProcessable  content,
        String          encryptionOID,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createKeyGenerator(encryptionOID, provider);

        return generate(content, encryptionOID, keyGen, provider);
    }


    /**
     * generate an enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     */
    public CMSEnvelopedData generate(
        CMSProcessable  content,
        String          encryptionOID,
        int             keySize,
        String          provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        KeyGenerator keyGen = CMSEnvelopedHelper.INSTANCE.createKeyGenerator(encryptionOID, provider);

        keyGen.init(keySize);

        return generate(content, encryptionOID, keyGen, provider);
    }
}
