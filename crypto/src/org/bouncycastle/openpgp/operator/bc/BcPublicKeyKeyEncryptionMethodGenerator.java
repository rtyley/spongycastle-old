package org.bouncycastle.openpgp.operator.bc;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PublicKeyKeyEncryptionMethodGenerator;

public class BcPublicKeyKeyEncryptionMethodGenerator
    extends PublicKeyKeyEncryptionMethodGenerator
{
    private SecureRandom random;
    private BcPGPKeyConverter keyConverter = new BcPGPKeyConverter();

    public BcPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey key)
    {
        super(key);
    }

    public BcPublicKeyKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        this.random = random;

        return this;
    }

    protected byte[] encryptSessionInfo(PGPPublicKey pubKey, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            AsymmetricBlockCipher c = BcImplProvider.createPublicKeyCipher(pubKey.getAlgorithm());

            AsymmetricKeyParameter key = keyConverter.getPublicKey(pubKey);

            if (random == null)
            {
                random = new SecureRandom();
            }

            c.init(true, new ParametersWithRandom(key, random));

            return c.processBlock(sessionInfo, 0, sessionInfo.length);
        }
        catch (InvalidCipherTextException e)
        {
            throw new PGPException("exception encrypting session info: " + e.getMessage(), e);
        }
    }
}
