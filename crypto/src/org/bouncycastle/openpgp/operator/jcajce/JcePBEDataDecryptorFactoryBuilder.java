package org.bouncycastle.openpgp.operator.jcajce;

import java.security.Provider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;

public class JcePBEDataDecryptorFactoryBuilder
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());
    private PGPDigestCalculatorProvider calculatorProvider;

    public JcePBEDataDecryptorFactoryBuilder(PGPDigestCalculatorProvider calculatorProvider)
    {
        this.calculatorProvider = calculatorProvider;
    }

    public JcePBEDataDecryptorFactoryBuilder setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcePBEDataDecryptorFactoryBuilder setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public PBEDataDecryptorFactory build(char[] passPhrase)
    {
         return new PBEDataDecryptorFactory(passPhrase, calculatorProvider)
         {
             public byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] secKeyData)
                 throws PGPException
             {
                 try
                 {
                     if (secKeyData != null && secKeyData.length > 0)
                     {
                         String cipherName = PGPUtil.getSymmetricCipherName(keyAlgorithm);
                         Cipher keyCipher = helper.createCipher(cipherName + "/CFB/NoPadding");

                         keyCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, cipherName), new IvParameterSpec(new byte[keyCipher.getBlockSize()]));

                         return keyCipher.doFinal(secKeyData);
                     }
                     else
                     {
                         byte[] keyBytes = new byte[key.length + 1];

                         keyBytes[0] = (byte)keyAlgorithm;
                         System.arraycopy(key, 0, keyBytes, 1, key.length);

                         return keyBytes;
                     }
                 }
                 catch (Exception e)
                 {
                     throw new PGPException("Exception recovering session info", e);
                 }
             }

             public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
                 throws PGPException
             {
                 return helper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
             }
         };
    }
}
