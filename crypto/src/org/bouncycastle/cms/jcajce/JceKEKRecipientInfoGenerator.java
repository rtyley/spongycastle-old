package org.bouncycastle.cms.jcajce;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.cms.KEKIdentifier;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KEKRecipientInfoGenerator;

public class JceKEKRecipientInfoGenerator
    extends KEKRecipientInfoGenerator
{
    private final SecretKey keyEncryptionKey;

    private EnvelopedDataHelper helper = new DefaultEnvelopedDataHelper();
    private SecureRandom random;

    public JceKEKRecipientInfoGenerator(SecretKey keyEncryptionKey, KEKIdentifier kekIdentifier)
    {
        super(kekIdentifier, determineKeyEncAlg(keyEncryptionKey));
        this.keyEncryptionKey = keyEncryptionKey;
    }

    public JceKEKRecipientInfoGenerator(SecretKey keyEncryptionKey, byte[] keyIdentifier)
    {
        this(keyEncryptionKey, new KEKIdentifier(keyIdentifier, null, null));
    }

    public JceKEKRecipientInfoGenerator setProvider(Provider provider)
    {
        this.helper = new ProviderEnvelopedDataHelper(provider);

        return this;
    }

    public JceKEKRecipientInfoGenerator setProvider(String providerName)
    {
        this.helper = new NamedEnvelopedDataHelper(providerName);

        return this;
    }

    public JceKEKRecipientInfoGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] contentEncryptionKey)
        throws CMSException
    {
        SecretKeySpec contentEncryptionKeySpec = new SecretKeySpec(contentEncryptionKey, "WRAP");

        Cipher keyEncryptionCipher = helper.createCipher(keyEncryptionAlgorithm.getAlgorithm());

        try
        {
            keyEncryptionCipher.init(Cipher.WRAP_MODE, keyEncryptionKey, random);

            return keyEncryptionCipher.wrap(contentEncryptionKeySpec);
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot process content encryption key: " + e.getMessage(), e);
        }
    }

    private static AlgorithmIdentifier determineKeyEncAlg(SecretKey key)
    {
        String algorithm = key.getAlgorithm();

        if (algorithm.startsWith("DES"))
        {
            return new AlgorithmIdentifier(new DERObjectIdentifier(
                    "1.2.840.113549.1.9.16.3.6"), new DERNull());
        }
        else if (algorithm.startsWith("RC2"))
        {
            return new AlgorithmIdentifier(new DERObjectIdentifier(
                    "1.2.840.113549.1.9.16.3.7"), new DERInteger(58));
        }
        else if (algorithm.startsWith("AES"))
        {
            int length = key.getEncoded().length * 8;
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

            return new AlgorithmIdentifier(wrapOid); // parameters absent
        }
        else if (algorithm.startsWith("SEED"))
        {
            // parameters absent
            return new AlgorithmIdentifier(
                    KISAObjectIdentifiers.id_npki_app_cmsSeed_wrap);
        }
        else if (algorithm.startsWith("Camellia"))
        {
            int length = key.getEncoded().length * 8;
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
                throw new IllegalArgumentException(
                        "illegal keysize in Camellia");
            }

            return new AlgorithmIdentifier(wrapOid); // parameters must be
                                                     // absent
        }
        else
        {
            throw new IllegalArgumentException("unknown algorithm");
        }
    }
}
