package org.bouncycastle.openpgp.operator.bc;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.openpgp.PBEDataDecryptorFactory;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;

public class BcPBEDataDecryptorFactory
    extends PBEDataDecryptorFactory
{
    public BcPBEDataDecryptorFactory(char[] pass, BcPGPDigestCalculatorProvider calculatorProvider)
    {
        super(pass, calculatorProvider);
    }

    public byte[] recoverSessionData(int keyAlgorithm, byte[] key, byte[] secKeyData)
        throws PGPException
    {
        try
        {
            if (secKeyData != null && secKeyData.length > 0)
            {
                BlockCipher engine = BcImplProvider.createBlockCipher(keyAlgorithm);
                BufferedBlockCipher cipher = BcUtil.createSymmetricKeyWrapper(false, engine, key);

                byte[] out = new byte[secKeyData.length];

                int len = cipher.processBytes(secKeyData, 0, secKeyData.length, out, 0);

                len += cipher.doFinal(out, len);

                return out;
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
        BlockCipher engine = BcImplProvider.createBlockCipher(encAlgorithm);

        return BcUtil.createDataDecryptor(withIntegrityPacket, engine, key);
    }
}
