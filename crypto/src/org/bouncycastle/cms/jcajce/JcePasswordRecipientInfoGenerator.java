package org.bouncycastle.cms.jcajce;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.PasswordRecipientInfoGenerator;

public class JcePasswordRecipientInfoGenerator
    extends PasswordRecipientInfoGenerator
{
    private final SecretKey keyEncryptionKey;

    private EnvelopedDataHelper helper = new DefaultEnvelopedDataHelper();
    private SecureRandom random;

    public JcePasswordRecipientInfoGenerator(char[] password, byte[] salt, int iterationCount, ASN1ObjectIdentifier kekAlgorithm)
    {
        super(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(salt, iterationCount)), kekAlgorithm, new SecureRandom());

//        PasswordIntRecipientInfoGenerator prig = new PasswordIntRecipientInfoGenerator();
//        prig.setKeyDerivationAlgorithm(, params));
//        prig.setKeyEncryptionKey(new SecretKeySpec(pbeKey.getEncoded(kekAlgorithmOid), kekAlgorithmOid));

        this.keyEncryptionKey = null; // TODO: need to accommodate two key types
    }

    public JcePasswordRecipientInfoGenerator setProvider(Provider provider)
    {
        this.helper = new ProviderEnvelopedDataHelper(provider);

        return this;
    }

    public JcePasswordRecipientInfoGenerator setProvider(String providerName)
    {
        this.helper = new NamedEnvelopedDataHelper(providerName);

        return this;
    }

    public byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] contentEncryptionKey)
        throws CMSException
    {
        SecretKeySpec contentEncryptionKeySpec = new SecretKeySpec(contentEncryptionKey, "WRAP");
        Cipher keyEncryptionCipher = helper.createRFC3211Wrapper(keyEncryptionAlgorithm.getAlgorithm());

        try
        {
            IvParameterSpec ivSpec = new IvParameterSpec(ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets());

            keyEncryptionCipher.init(Cipher.WRAP_MODE, keyEncryptionKey, ivSpec);

            return keyEncryptionCipher.wrap(contentEncryptionKeySpec);
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("cannot process content encryption key: " + e.getMessage(), e);
        }
    }
}