package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.jce.interfaces.GOST3410Key;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.DSAKey;
import java.security.spec.AlgorithmParameterSpec;

public class JDKDSASigner
    extends SignatureSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private Digest                  digest;
    private DSA                     signer;
    private SecureRandom            random;

    protected JDKDSASigner(
        Digest                  digest,
        DSA                     signer)
    {
        this.digest = digest;
        this.signer = signer;
    }

    protected void engineInitVerify(
        PublicKey   publicKey)
        throws InvalidKeyException
    {
        CipherParameters    param;

        if (publicKey instanceof GOST3410Key)
        {
            param = GOST3410Util.generatePublicKeyParameter(publicKey);
        }
        else if (publicKey instanceof DSAKey)
        {
            param = DSAUtil.generatePublicKeyParameter(publicKey);
        }
        else
        {
            try
            {
                byte[]  bytes = publicKey.getEncoded();

                publicKey = JDKKeyFactory.createPublicKeyFromDERStream(bytes);

                if (publicKey instanceof DSAKey)
                {
                    param = DSAUtil.generatePublicKeyParameter(publicKey);
                }
                else
                {
                    throw new InvalidKeyException("can't recognise key type in DSA based signer");
                }
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("can't recognise key type in DSA based signer");
            }
        }

        digest.reset();
        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey      privateKey,
        SecureRandom    random)
        throws InvalidKeyException
    {
        this.random = random;
        engineInitSign(privateKey);
    }

    protected void engineInitSign(
        PrivateKey  privateKey)
        throws InvalidKeyException
    {
        CipherParameters    param;

        if (privateKey instanceof GOST3410Key)
        {
            param = GOST3410Util.generatePrivateKeyParameter(privateKey);
        }
        else
        {
            param = DSAUtil.generatePrivateKeyParameter(privateKey);
        }

        digest.reset();

        if (random != null)
        {
            signer.init(true, new ParametersWithRandom(param, random));
        }
        else
        {
            signer.init(true, param);
        }
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        try
        {
            BigInteger[]    sig = signer.generateSignature(hash);

            return derEncode(sig[0], sig[1]);
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        BigInteger[]    sig;

        try
        {
            sig = derDecode(sigBytes);
        }
        catch (Exception e)
        {
            throw new SignatureException("error decoding signature bytes.");
        }

        return signer.verifySignature(hash, sig[0], sig[1]);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
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

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String      param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    private byte[] derEncode(
        BigInteger  r,
        BigInteger  s)
        throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        DEROutputStream         dOut = new DEROutputStream(bOut);
        ASN1EncodableVector     v = new ASN1EncodableVector();

        v.add(new DERInteger(r));
        v.add(new DERInteger(s));

        dOut.writeObject(new DERSequence(v));

        return bOut.toByteArray();
    }

    private BigInteger[] derDecode(
        byte[]  encoding)
        throws IOException
    {
        ASN1InputStream         aIn = new ASN1InputStream(encoding);
        ASN1Sequence            s = (ASN1Sequence)aIn.readObject();

        BigInteger[]            sig = new BigInteger[2];

        sig[0] = ((DERInteger)s.getObjectAt(0)).getValue();
        sig[1] = ((DERInteger)s.getObjectAt(1)).getValue();

        return sig;
    }

    static public class stdDSA
        extends JDKDSASigner
    {
        public stdDSA()
        {
            super(new SHA1Digest(), new DSASigner());
        }
    }

    static public class dsa224
        extends JDKDSASigner
    {
        public dsa224()
        {
            super(new SHA224Digest(), new DSASigner());
        }
    }
    
    static public class dsa256
        extends JDKDSASigner
    {
        public dsa256()
        {
            super(new SHA256Digest(), new DSASigner());
        }
    }
    
    static public class dsa384
        extends JDKDSASigner
    {
        public dsa384()
        {
            super(new SHA384Digest(), new DSASigner());
        }
    }
    
    static public class dsa512
        extends JDKDSASigner
    {
        public dsa512()
        {
            super(new SHA512Digest(), new DSASigner());
        }
    }

    static public class noneDSA
        extends JDKDSASigner
    {
        public noneDSA()
        {
            super(new NullDigest(), new DSASigner());
        }
    }
    
    private static class NullDigest
        implements Digest
    {
        private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
        public String getAlgorithmName()
        {
            return "NULL";
        }
    
        public int getDigestSize()
        {
            return bOut.size();
        }
    
        public void update(byte in)
        {
            bOut.write(in);
        }
    
        public void update(byte[] in, int inOff, int len)
        {
            bOut.write(in, inOff, len);
        }
    
        public int doFinal(byte[] out, int outOff)
        {
            byte[] res = bOut.toByteArray();
            
            System.arraycopy(res, 0, out, outOff, res.length);
            
            return res.length;
        }
    
        public void reset()
        {
            bOut.reset();
        }
    }
}
