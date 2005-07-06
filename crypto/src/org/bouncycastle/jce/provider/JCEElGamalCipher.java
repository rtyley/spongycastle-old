package org.bouncycastle.jce.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHKey;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.BufferedAsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jce.interfaces.ElGamalKey;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;

public class JCEElGamalCipher extends WrapCipherSpi
{
    private BufferedAsymmetricBlockCipher   cipher;
    private boolean                         publicKeyOnly = false;
    private boolean                         privateKeyOnly = false;

    public JCEElGamalCipher(
        AsymmetricBlockCipher   engine)
    {
        cipher = new BufferedAsymmetricBlockCipher(engine);
    }

    public JCEElGamalCipher(
        boolean                 publicKeyOnly,
        boolean                 privateKeyOnly,
        AsymmetricBlockCipher   engine)
    {
        this.publicKeyOnly = publicKeyOnly;
        this.privateKeyOnly = privateKeyOnly;
        cipher = new BufferedAsymmetricBlockCipher(engine);
    }
        
    protected int engineGetBlockSize() 
    {
        return cipher.getInputBlockSize();
    }

    protected byte[] engineGetIV() 
    {
        return null;
    }

    protected int engineGetKeySize(
        Key     key) 
    {
        if (key instanceof ElGamalKey)
        {
            ElGamalKey   k = (ElGamalKey)key;

            return k.getParameters().getP().bitLength();
        }
        else if (key instanceof DHKey)
        {
            DHKey   k = (DHKey)key;

            return k.getParams().getP().bitLength();
        }

        throw new IllegalArgumentException("not an ElGamal key!");
    }

    protected int engineGetOutputSize(
        int     inputLen) 
    {
        return cipher.getOutputBlockSize();
    }

    protected AlgorithmParameters engineGetParameters() 
    {
        return null;
    }

    protected void engineSetMode(
        String  mode) 
        throws NoSuchAlgorithmException
    {
        throw new NoSuchAlgorithmException("can't support mode " + mode);
    }

    protected void engineSetPadding(
        String  padding) 
        throws NoSuchPaddingException
    {
        throw new NoSuchPaddingException(padding + " unavailable with ElGamal.");
    }

    protected void engineInit(
        int                     opmode,
        Key                     key,
        AlgorithmParameterSpec  params,
        SecureRandom            random) 
    throws InvalidKeyException
    {
        CipherParameters        param;

        if (params == null)
        {
            if (key instanceof ElGamalPublicKey)
            {
                param = ElGamalUtil.generatePublicKeyParameter((PublicKey)key);
            }
            else if (key instanceof ElGamalPrivateKey)
            {
                param = ElGamalUtil.generatePrivateKeyParameter((PrivateKey)key);
            }
            else
            {
                throw new InvalidKeyException("unknown key type passed to ElGamal");
            }
        }
        else
        {
            throw new IllegalArgumentException("unknown parameter type.");
        }

        if (random != null)
        {
            param = new ParametersWithRandom(param, random);
        }

        switch (opmode)
        {
        case Cipher.ENCRYPT_MODE:
        case Cipher.WRAP_MODE:
            cipher.init(true, param);
            break;
        case Cipher.DECRYPT_MODE:
        case Cipher.UNWRAP_MODE:
            cipher.init(false, param);
            break;
        default:
            System.out.println("eeek!");
        }
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        AlgorithmParameters params,
        SecureRandom        random) 
    throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("can't handle parameters in ElGamal");
    }

    protected void engineInit(
        int                 opmode,
        Key                 key,
        SecureRandom        random) 
    throws InvalidKeyException
    {
        engineInit(opmode, key, (AlgorithmParameterSpec)null, random);
    }

    protected byte[] engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen) 
    {
        cipher.processBytes(input, inputOffset, inputLen);
        return null;
    }

    protected int engineUpdate(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset) 
    {
        cipher.processBytes(input, inputOffset, inputLen);
        return 0;
    }

    protected byte[] engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen) 
        throws IllegalBlockSizeException, BadPaddingException
    {
        cipher.processBytes(input, inputOffset, inputLen);
        try
        {
            return cipher.doFinal();
        }
        catch (InvalidCipherTextException e)
        {
            throw new BadPaddingException(e.getMessage());
        }
    }

    protected int engineDoFinal(
        byte[]  input,
        int     inputOffset,
        int     inputLen,
        byte[]  output,
        int     outputOffset) 
        throws IllegalBlockSizeException, BadPaddingException
    {
        byte[]  out;

        cipher.processBytes(input, inputOffset, inputLen);

        try
        {
            out = cipher.doFinal();
        }
        catch (InvalidCipherTextException e)
        {
            throw new BadPaddingException(e.getMessage());
        }

        for (int i = 0; i != out.length; i++)
        {
            output[outputOffset + i] = out[i];
        }

        return out.length;
    }

    /**
     * classes that inherit from us.
     */
    static public class NoPadding
        extends JCEElGamalCipher
    {
        public NoPadding()
        {
            super(new ElGamalEngine());
        }
    }
    
    static public class PKCS1v1_5Padding
        extends JCEElGamalCipher
    {
        public PKCS1v1_5Padding()
        {
            super(new PKCS1Encoding(new ElGamalEngine()));
        }
    }
}
