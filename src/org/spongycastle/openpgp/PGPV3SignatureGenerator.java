package org.spongycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;

import org.spongycastle.bcpg.MPInteger;
import org.spongycastle.bcpg.OnePassSignaturePacket;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.SignaturePacket;

/**
 * Generator for old style PGP V3 Signatures.
 */
public class PGPV3SignatureGenerator
{
    private int keyAlgorithm;
    private int hashAlgorithm;
    private PGPPrivateKey privKey;
    private Signature sig;
    private MessageDigest dig;
    private int signatureType;
    
    private byte            lastb;
    
    /**
     * Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.
     * 
     * @param keyAlgorithm
     * @param hashAlgorithm
     * @param provider
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
     public PGPV3SignatureGenerator(
        int  keyAlgorithm,
        int  hashAlgorithm,
        String provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, PGPException
    {
        this(keyAlgorithm, hashAlgorithm, PGPUtil.getProvider(provider));
    }

    public PGPV3SignatureGenerator(
        int  keyAlgorithm,
        int  hashAlgorithm,
        Provider provider)
        throws NoSuchAlgorithmException, PGPException
    {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        
        dig = PGPUtil.getDigestInstance(PGPUtil.getDigestName(hashAlgorithm), provider);
        sig = Signature.getInstance(PGPUtil.getSignatureName(keyAlgorithm, hashAlgorithm), provider);
    }
    
    /**
     * Initialise the generator for signing.
     * 
     * @param signatureType
     * @param key
     * @throws PGPException
     */
    public void initSign(
        int           signatureType,
        PGPPrivateKey key)
        throws PGPException
    {
        initSign(signatureType, key, null);
    }

    /**
     * Initialise the generator for signing.
     * 
     * @param signatureType
     * @param key
     * @param random
     * @throws PGPException
     */
    public void initSign(
        int           signatureType,
        PGPPrivateKey key,
        SecureRandom  random)
        throws PGPException
    {
        this.privKey = key;
        this.signatureType = signatureType;
        
        try
        {
            if (random == null)
            {
                sig.initSign(key.getKey());
            }
            else
            {
                sig.initSign(key.getKey(), random);
            }
        }
        catch (InvalidKeyException e)
        {
           throw new PGPException("invalid key.", e);
        }
        
        dig.reset();
        lastb = 0;
    }
    
    public void update(
        byte b) 
        throws SignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            if (b == '\r')
            {
                sig.update((byte)'\r');
                sig.update((byte)'\n');
                dig.update((byte)'\r');
                dig.update((byte)'\n');
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    sig.update((byte)'\r');
                    sig.update((byte)'\n');
                    dig.update((byte)'\r');
                    dig.update((byte)'\n');
                }
            }
            else
            {
                sig.update(b);
                dig.update(b);
            }
            
            lastb = b;
        }
        else
        {
            sig.update(b);
            dig.update(b);
        }
    }
    
    public void update(
        byte[] b) 
        throws SignatureException
    {
        this.update(b, 0, b.length);
    }
    
    public void update(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            int finish = off + len;
            
            for (int i = off; i != finish; i++)
            {
                this.update(b[i]);
            }
        }
        else
        {
            sig.update(b, off, len);
            dig.update(b, off, len);
        }
    }
    
    /**
     * Return the one pass header associated with the current signature.
     * 
     * @param isNested
     * @return PGPOnePassSignature
     * @throws PGPException
     */
    public PGPOnePassSignature generateOnePassVersion(
        boolean isNested)
        throws PGPException
    {
        return new PGPOnePassSignature(new OnePassSignaturePacket(signatureType, hashAlgorithm, keyAlgorithm, privKey.getKeyID(), isNested));
    }
    
    /**
     * Return a V3 signature object containing the current signature state.
     * 
     * @return PGPSignature
     * @throws PGPException
     * @throws SignatureException
     */
    public PGPSignature generate()
            throws PGPException, SignatureException
    {
        long creationTime = new Date().getTime() / 1000;

        ByteArrayOutputStream sOut = new ByteArrayOutputStream();

        sOut.write(signatureType);
        sOut.write((byte)(creationTime >> 24));
        sOut.write((byte)(creationTime >> 16));
        sOut.write((byte)(creationTime >> 8));
        sOut.write((byte)creationTime);

        byte[] hData = sOut.toByteArray();

        sig.update(hData);
        dig.update(hData);

        MPInteger[] sigValues;
        if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_SIGN
            || keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL)
            // an RSA signature
        {
            sigValues = new MPInteger[1];
            sigValues[0] = new MPInteger(new BigInteger(1, sig.sign()));
        }
        else
        {
            sigValues = PGPUtil.dsaSigToMpi(sig.sign());
        }

        byte[] digest = dig.digest();
        byte[] fingerPrint = new byte[2];

        fingerPrint[0] = digest[0];
        fingerPrint[1] = digest[1];

        return new PGPSignature(new SignaturePacket(3, signatureType, privKey.getKeyID(), keyAlgorithm, hashAlgorithm, creationTime * 1000, fingerPrint, sigValues));
    }
}
