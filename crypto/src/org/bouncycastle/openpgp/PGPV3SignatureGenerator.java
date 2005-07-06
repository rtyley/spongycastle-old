package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignaturePacket;

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
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        
        dig = MessageDigest.getInstance(PGPUtil.getDigestName(hashAlgorithm), provider);
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
        this.privKey = key;
        this.signatureType = signatureType;
        
        try
        {
            sig.initSign(key.getKey());
        }
        catch (InvalidKeyException e)
        {
           throw new PGPException("invalid key.", e);
        }
        
        dig.reset();
    }
    
    public void update(
        byte b) 
        throws SignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            if (b == '\n')
            {
                sig.update((byte)'\r');
                sig.update((byte)'\n');
                dig.update((byte)'\r');
                dig.update((byte)'\n');
                return;
            }
            else if (b == '\r')
            {
                return;
            }
        }
        
        sig.update(b);
        dig.update(b);
    }
    
    public void update(
        byte[] b) 
        throws SignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            for (int i = 0; i != b.length; i++)
            {
                this.update(b[i]);
            }
        }
        else
        {
            sig.update(b);
            dig.update(b);
        }
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

            this.update(hData);

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
                ASN1InputStream aIn =
                    new ASN1InputStream(new ByteArrayInputStream(sig.sign()));

                DERInteger i1;
                DERInteger i2;

                try
                {
                    ASN1Sequence s = (ASN1Sequence)aIn.readObject();

                    i1 = (DERInteger)s.getObjectAt(0);
                    i2 = (DERInteger)s.getObjectAt(1);
                }
                catch (IOException e)
                {
                    throw new PGPException("exception encoding signature", e);
                }

                sigValues = new MPInteger[2];
                sigValues[0] = new MPInteger(i1.getValue());
                sigValues[1] = new MPInteger(i2.getValue());
            }

            byte[] digest = dig.digest();
            byte[] fingerPrint = new byte[2];

            fingerPrint[0] = digest[0];
            fingerPrint[1] = digest[1];

            return new PGPSignature(new SignaturePacket(3, signatureType, privKey.getKeyID(), keyAlgorithm, hashAlgorithm, creationTime * 1000, fingerPrint, sigValues));
    }
}
