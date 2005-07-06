package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.OnePassSignaturePacket;

/**
 * A one pass signature object.
 */
public class PGPOnePassSignature
{
    private OnePassSignaturePacket sigPack;
    private int                    signatureType;
    
    private Signature              sig;
    
    PGPOnePassSignature(
        BCPGInputStream    pIn)
        throws IOException, PGPException
    {
        this((OnePassSignaturePacket)pIn.readPacket());
    }
    
    PGPOnePassSignature(
        OnePassSignaturePacket    sigPack)
        throws PGPException
    {
        this.sigPack = sigPack;
        this.signatureType = sigPack.getSignatureType();
        
        try
        {
            this.sig = Signature.getInstance(PGPUtil.getSignatureName(sigPack.getKeyAlgorithm(), sigPack.getHashAlgorithm()), PGPUtil.getDefaultProvider());
        }
        catch (Exception e)
        {    
            throw new PGPException("can't set up signature object.",  e);
        }
    }
    
    /**
     * Initialise the signature object for verification.
     * 
     * @param pubKey
     * @param provider
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public void initVerify(
        PGPPublicKey    pubKey,
        String          provider)
        throws NoSuchProviderException, PGPException
    {    
        try
        {
            sig.initVerify(pubKey.getKey(provider));
        }
        catch (InvalidKeyException e)
        {
            throw new PGPException("invalid key.", e);
        }
    }
    
    public void update(
        byte    b)
        throws SignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            if (b == '\n')
            {
                sig.update((byte)'\r');
                sig.update((byte)'\n');
                return;
            }
            else if (b == '\r')
            {
                return;
            }
        }
        
        sig.update(b);
    }
    
    public void update(
        byte[]    bytes)
        throws SignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            for (int i = 0; i != bytes.length; i++)
            {
                this.update(bytes[i]);
            }
        }
        else
        {
            sig.update(bytes);
        }
    }
    
    public void update(
        byte[]    bytes,
        int       off,
        int       length)
        throws SignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            int finish = off + length;
            
            for (int i = off; i != finish; i++)
            {
                this.update(bytes[i]);
            }
        }
        else
        {
            sig.update(bytes, off, length);
        }
    }

    /**
     * Verify the calculated signature against the passed in PGPSignature.
     * 
     * @param pgpSig
     * @return boolean
     * @throws PGPException
     * @throws SignatureException
     */
    public boolean verify(
        PGPSignature    pgpSig)
        throws PGPException, SignatureException
    {
        byte[]            signature;

        sig.update(pgpSig.getSignatureTrailer());
        
        return sig.verify(pgpSig.getSignature());
    }
    
    public long getKeyID()
    {
        return sigPack.getKeyID();
    }
    
    public int getSignatureType()
    {
        return sigPack.getSignatureType();
    }
    
    public byte[] getEncoded() 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        
        this.encode(bOut);
        
        return bOut.toByteArray();
    }
    
    public void encode(
        OutputStream    outStream) 
        throws IOException
    {
        BCPGOutputStream    out;
        
        if (outStream instanceof BCPGOutputStream)
        {
            out = (BCPGOutputStream)outStream;
        }
        else
        {
            out = new BCPGOutputStream(outStream);
        }

        out.writePacket(sigPack);
    }
}
