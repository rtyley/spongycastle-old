package org.bouncycastle.cms.bc;

import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputEncryptor;

public class BcCMSContentBlockEncryptorBuilder
{
    private static Map keySizes = new HashMap();

    static
    {
        keySizes.put(CMSAlgorithm.AES128_CBC, new Integer(128));
        keySizes.put(CMSAlgorithm.AES192_CBC, new Integer(192));
        keySizes.put(CMSAlgorithm.AES256_CBC, new Integer(256));

        keySizes.put(CMSAlgorithm.CAMELLIA128_CBC, new Integer(128));
        keySizes.put(CMSAlgorithm.CAMELLIA192_CBC, new Integer(192));
        keySizes.put(CMSAlgorithm.CAMELLIA256_CBC, new Integer(256));

        keySizes.put(CMSAlgorithm.DES_EDE3_CBC, new Integer(192));
    }

    private static int getKeySize(ASN1ObjectIdentifier oid)
    {
        Integer size = (Integer)keySizes.get(oid);

        if (size != null)
        {
            return size.intValue();
        }

        return -1;
    }

    private final ASN1ObjectIdentifier encryptionOID;
    private final int                  keySize;
    private final BufferedBlockCipher  cipher;

    private SecureRandom random;

    public BcCMSContentBlockEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, BlockCipher engine)
    {
        this(encryptionOID, engine, getKeySize(encryptionOID));
    }

    public BcCMSContentBlockEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, BlockCipher engine, int keySize)
    {
        this.encryptionOID = encryptionOID;
        this.cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), new PKCS7Padding());
        this.keySize = keySize;
    }

    public BcCMSContentBlockEncryptorBuilder setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    public OutputEncryptor build()
        throws CMSException
    {
        return new CMSOutputEncryptor(encryptionOID, keySize, random);
    }

    private class CMSOutputEncryptor
        implements OutputEncryptor
    {
        private byte[] encKey;
        private AlgorithmIdentifier algorithmIdentifier;

        CMSOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
            throws CMSException
        {
            CipherKeyGenerator keyGenerator = BCUtils.createKeyGenerator(encryptionOID);

            if (random == null)
            {
                random = new SecureRandom();
            }

            keyGenerator.init(new KeyGenerationParameters(random, keySize));

            encKey= keyGenerator.generateKey();

            byte[] iv = new byte[cipher.getBlockSize()];

            cipher.init(true, new ParametersWithIV(new KeyParameter(encKey), iv));

            algorithmIdentifier = new AlgorithmIdentifier(encryptionOID, new DEROctetString(iv));
        }

        public AlgorithmIdentifier getAlgorithmIdentifier()
        {
            return algorithmIdentifier;
        }

        public OutputStream getOutputStream(OutputStream dOut)
        {
            return new CipherOutputStream(dOut, cipher);
        }

        public GenericKey getKey()
        {
            return new GenericKey(encKey);
        }
    }
}
