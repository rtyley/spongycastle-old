package org.bouncycastle.cavp.jce;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.cavp.test.CryptoProcessor;
import org.bouncycastle.cavp.test.CryptoProcessorFactory;

public class JceCryptoProcessorFactory
    implements CryptoProcessorFactory
{
    private final String algorithm;
    private final Cipher cipher;

    public JceCryptoProcessorFactory(String algorithm)
        throws GeneralSecurityException
    {
        this.algorithm = algorithm;
        this.cipher = Cipher.getInstance(algorithm, "BC");
    }

    public CryptoProcessor getDecryptor()
    {
        return new CryptoProcessor()
        {
            public void init(byte[] key)
                throws GeneralSecurityException
            {
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm.substring(0, algorithm.indexOf('/'))));
            }

            public void init(byte[] key, byte[] iv)
                throws GeneralSecurityException
            {
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, algorithm.substring(0, algorithm.indexOf('/'))), new IvParameterSpec(iv));
            }

            public byte[] process(byte[] in)
                throws GeneralSecurityException
            {
                return cipher.doFinal(in);
            }
        };
    }

    public CryptoProcessor getEncryptor()
    {
        return new CryptoProcessor()
        {
            public void init(byte[] key)
                throws GeneralSecurityException
            {
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm.substring(0, algorithm.indexOf('/'))));
            }

            public void init(byte[] key, byte[] iv)
                throws GeneralSecurityException
            {
                cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, algorithm.substring(0, algorithm.indexOf('/'))), new IvParameterSpec(iv));
            }

            public byte[] process(byte[] in)
                throws GeneralSecurityException
            {
                return cipher.doFinal(in);
            }
        };
    }
}
