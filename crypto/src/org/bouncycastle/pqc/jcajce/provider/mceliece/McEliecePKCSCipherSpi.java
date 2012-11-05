package org.bouncycastle.pqc.jcajce.provider.mceliece;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePKCSCipher;
import org.bouncycastle.pqc.jcajce.provider.util.AsymmetricBlockCipher;

public class McEliecePKCSCipherSpi
    extends AsymmetricBlockCipher
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    // TODO digest needed?
    private Digest digest;
    private McEliecePKCSCipher cipher;

    public McEliecePKCSCipherSpi(Digest digest, McEliecePKCSCipher cipher)
    {
        this.digest = digest;
        this.cipher = cipher;
    }

    @Override
    protected void initCipherEncrypt(Key key, AlgorithmParameterSpec params,
                                     SecureRandom sr)
        throws InvalidKeyException,
        InvalidAlgorithmParameterException
    {

        CipherParameters param;
        param = McElieceKeysToParams.generatePublicKeyParameter((PublicKey)key);

        param = new ParametersWithRandom(param, sr);
        digest.reset();
        cipher.init(true, param);
        this.maxPlainTextSize = cipher.maxPlainTextSize;
        this.cipherTextSize = cipher.cipherTextSize;
    }

    @Override
    protected void initCipherDecrypt(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        CipherParameters param;
        param = McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey)key);

        digest.reset();
        cipher.init(false, param);
        this.maxPlainTextSize = cipher.maxPlainTextSize;
        this.cipherTextSize = cipher.cipherTextSize;
    }

    @Override
    protected byte[] messageEncrypt(byte[] input)
        throws IllegalBlockSizeException, BadPaddingException
    {
        byte[] output = null;
        try
        {
            output = cipher.messageEncrypt(input);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return output;
    }

    @Override
    protected byte[] messageDecrypt(byte[] input)
        throws IllegalBlockSizeException, BadPaddingException
    {
        byte[] output = null;
        try
        {
            output = cipher.messageDecrypt(input);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return output;
    }

    @Override
    public String getName()
    {
        return "McEliecePKCS";
    }

    @Override
    public int getKeySize(Key key)
        throws InvalidKeyException
    {
        McElieceKeyParameters mcElieceKeyParameters;
        if (key instanceof PublicKey)
        {
            mcElieceKeyParameters = (McElieceKeyParameters)McElieceKeysToParams.generatePublicKeyParameter((PublicKey)key);
        }
        else
        {
            mcElieceKeyParameters = (McElieceKeyParameters)McElieceKeysToParams.generatePrivateKeyParameter((PrivateKey)key);

        }


        return cipher.getKeySize(mcElieceKeyParameters);
    }

    //////////////////////////////////////////////////////////////////////////////////

    static public class stdMcEliecePKCS
        extends McEliecePKCSCipherSpi
    {
        public stdMcEliecePKCS()
        {
            super(new SHA1Digest(), new McEliecePKCSCipher());
        }
    }

    static public class McEliecePKCS1
        extends McEliecePKCSCipherSpi
    {

        public McEliecePKCS1()
        {
            super(new SHA1Digest(), new McEliecePKCSCipher());
        }
    }

    static public class McEliecePKCS224
        extends McEliecePKCSCipherSpi
    {
        public McEliecePKCS224()
        {
            super(new SHA224Digest(), new McEliecePKCSCipher());
        }
    }

    static public class McEliecePKCS256
        extends McEliecePKCSCipherSpi
    {
        public McEliecePKCS256()
        {
            super(new SHA256Digest(), new McEliecePKCSCipher());
        }
    }

    static public class McEliecePKCS384
        extends McEliecePKCSCipherSpi
    {
        public McEliecePKCS384()
        {
            super(new SHA384Digest(), new McEliecePKCSCipher());
        }
    }

    static public class McEliecePKCS512
        extends McEliecePKCSCipherSpi
    {
        public McEliecePKCS512()
        {
            super(new SHA512Digest(), new McEliecePKCSCipher());
        }
    }


}
