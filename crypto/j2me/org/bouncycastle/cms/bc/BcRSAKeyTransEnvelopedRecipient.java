package org.bouncycastle.cms.bc;

import java.io.InputStream;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.operator.InputDecryptor;

public class BcRSAKeyTransEnvelopedRecipient
    extends BcRSAKeyTransRecipient
{
    public BcRSAKeyTransEnvelopedRecipient(AsymmetricKeyParameter recipientKey)
    {
        super(recipientKey);
    }

    private BufferedBlockCipher createContentCipher(CipherParameters secretKey, AlgorithmIdentifier contentEncryptionAlgorithm)
    {
        ASN1ObjectIdentifier alg = contentEncryptionAlgorithm.getAlgorithm();
        BlockCipher          engine;

        if (alg.equals(NISTObjectIdentifiers.id_aes128_CBC) || alg.equals(NISTObjectIdentifiers.id_aes256_CBC) || alg.equals(NISTObjectIdentifiers.id_aes192_CBC))
        {
             engine = new CBCBlockCipher(new AESEngine());
        }
        else if (alg.equals(CMSAlgorithm.DES_EDE3_CBC))
        {
             engine = new CBCBlockCipher(new DESedeEngine());
        }
        else
        {
            throw new IllegalStateException("unknown algorithm encountered");
        }

        engine.init(false, secretKey);

        return new PaddedBufferedBlockCipher(engine, new PKCS7Padding());
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        CipherParameters secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final BufferedBlockCipher dataCipher = createContentCipher(secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputDecryptor()
        {
            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataIn)
            {
                return new CipherInputStream(dataIn, dataCipher);
            }
        });
    }
}
