package org.bouncycastle.cms.jcajce;

import java.io.OutputStream;
import java.security.Provider;
import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OutputEncryptor;

public class JceCMSContentEncryptorBuilder
{
    private final ASN1ObjectIdentifier encryptionOID;
    private final int                  keySize;

    private EnvelopedDataHelper helper = new DefaultEnvelopedDataHelper();
    private SecureRandom random;

    public JceCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID)
    {
        this(encryptionOID, -1);
    }

    public JceCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize)
    {
        this.encryptionOID = encryptionOID;
        this.keySize = keySize;
    }

    public JceCMSContentEncryptorBuilder setProvider(Provider provider)
    {
        this.helper = new ProviderEnvelopedDataHelper(provider);

        return this;
    }

    public JceCMSContentEncryptorBuilder setProvider(String providerName)
    {
        this.helper = new NamedEnvelopedDataHelper(providerName);

        return this;
    }

    public JceCMSContentEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public OutputEncryptor build()
        throws CMSException
    {
        helper.initForEncryption(encryptionOID, keySize, random);

        return new OutputEncryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return helper.getAlgorithmIdentifier();
            }

            public OutputStream getOutputStream(OutputStream dOut)
            {
                return helper.getCipherOutputStream(dOut);
            }

            public byte[] getEncodedKey()
            {
                return helper.getEncKey();
            }
        };
    }
}
