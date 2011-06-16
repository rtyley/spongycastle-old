package org.bouncycastle.openpgp.operator.jcajce;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.openpgp.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

public class JcePBEKeyEncryptionMethodGenerator
    extends PBEKeyEncryptionMethodGenerator
{
    private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

    public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase, PGPDigestCalculator s2kDigestCalculator)
    {
        super(passPhrase, s2kDigestCalculator);
    }

    public JcePBEKeyEncryptionMethodGenerator(char[] passPhrase)
    {
        super(passPhrase, new SHA1PGPDigestCalculator());
    }

    public JcePBEKeyEncryptionMethodGenerator setProvider(Provider provider)
    {
        this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

        return this;
    }

    public JcePBEKeyEncryptionMethodGenerator setProvider(String providerName)
    {
        this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

        return this;
    }

    public JcePBEKeyEncryptionMethodGenerator setSecureRandom(SecureRandom random)
    {
        super.setSecureRandom(random);

        return this;
    }

    protected byte[] encryptSessionInfo(int encAlgorithm, byte[] key, byte[] sessionInfo)
        throws PGPException
    {
        try
        {
            String cName = PGPUtil.getSymmetricCipherName(encAlgorithm);
            Cipher c = helper.createCipher(cName + "/CFB/NoPadding");
            SecretKey sKey = new SecretKeySpec(key, PGPUtil.getSymmetricCipherName(encAlgorithm));

            c.init(Cipher.ENCRYPT_MODE, sKey, new IvParameterSpec(new byte[c.getBlockSize()]));

            return c.doFinal(sessionInfo, 0, sessionInfo.length);
        }
        catch (IllegalBlockSizeException e)
        {
            throw new PGPException("illegal block size: " + e.getMessage(), e);
        }
        catch (BadPaddingException e)
        {
            throw new PGPException("bad padding: " + e.getMessage(), e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new PGPException("IV invalid: " + e.getMessage(), e);
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("key invalid: " + e.getMessage(), e);
        }
    }
}
