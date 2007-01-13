package org.bouncycastle.jce.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PSSSigner;

public class JDKPSSSigner
    extends Signature
{
    private AsymmetricBlockCipher signer;
    private Digest digest;
    private int saltLength;
    private AlgorithmParameters engineParams;
    private PSSSigner pss;

    protected JDKPSSSigner(
        String name,
        AsymmetricBlockCipher signer,
        Digest digest)
    {
        super(name);

        this.signer = signer;
        this.digest = digest;
        if (digest != null)
        {
            this.saltLength = digest.getDigestSize();
        }
        else
        {
            this.saltLength = 20;
        }
    }

    protected void engineInitVerify(
        PublicKey   publicKey)
        throws InvalidKeyException
    {
        if (!(publicKey instanceof RSAPublicKey))
        {
            throw new InvalidKeyException("Supplied key is not a RSAPublicKey instance");
        }

        pss = new PSSSigner(signer, digest, saltLength);
        pss.init(false,
            RSAUtil.generatePublicKeyParameter((RSAPublicKey)publicKey));
    }

    protected void engineInitSign(
        PrivateKey      privateKey,
        SecureRandom    random)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof RSAPrivateKey))
        {
            throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
        }

        pss = new PSSSigner(signer, digest, saltLength);
        pss.init(true, new ParametersWithRandom(RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey), random));
    }

    protected void engineInitSign(
        PrivateKey  privateKey)
        throws InvalidKeyException
    {
        if (!(privateKey instanceof RSAPrivateKey))
        {
            throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance");
        }

        pss = new PSSSigner(signer, digest, saltLength);
        pss.init(true, RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)privateKey));
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        pss.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        pss.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        try
        {
            return pss.generateSignature();
        }
        catch (CryptoException e)
        {
            throw new SignatureException(e.getMessage());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        return pss.verifySignature(sigBytes);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
        throws InvalidParameterException
    {
        if (params instanceof PSSParameterSpec)
        {
            saltLength = ((PSSParameterSpec)params).getSaltLength();
        }
        else
        {
            throw new InvalidParameterException("Only PSSParameterSpec supported");
        }
    }
    
    protected AlgorithmParameters engineGetParameters() 
    {
        if (engineParams == null)
        {
            try
            {
                engineParams = AlgorithmParameters.getInstance("PSS", "BC");
                engineParams.init(new PSSParameterSpec(saltLength));
            }
            catch (Exception e)
            {
                throw new RuntimeException(e.toString());
            }
        }

        return engineParams;
    }

    /**
     * @deprecated replaced with <a href = "#engineSetParameter(java.security.spec.AlgorithmParameterSpec)">
     */
    protected void engineSetParameter(
        String  param,
        Object  value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
    
    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("engineGetParameter unsupported");
    }

    static public class PSSwithRSA
        extends JDKPSSSigner
    {
        public PSSwithRSA()
        {
            super("SHA1withRSAandMGF1", new RSABlindedEngine(), null);
        }
    }

    static public class SHA1withRSA
        extends JDKPSSSigner
    {
        public SHA1withRSA()
        {
            super("SHA1withRSAandMGF1", new RSABlindedEngine(), new SHA1Digest());
        }
    }

    static public class SHA224withRSA
        extends JDKPSSSigner
    {
        public SHA224withRSA()
        {
            super("SHA224withRSAandMGF1", new RSABlindedEngine(), new SHA224Digest());
        }
    }

    static public class SHA256withRSA
        extends JDKPSSSigner
    {
        public SHA256withRSA()
        {
            super("SHA256withRSAandMGF1", new RSABlindedEngine(), new SHA256Digest());
        }
    }

    static public class SHA384withRSA
        extends JDKPSSSigner
    {
        public SHA384withRSA()
        {
            super("SHA384withRSAandMGF1", new RSABlindedEngine(), new SHA384Digest());
        }
    }

    static public class SHA512withRSA
        extends JDKPSSSigner
    {
        public SHA512withRSA()
        {
            super("SHA512withRSAandMGF1", new RSABlindedEngine(), new SHA512Digest());
        }
    }
}
