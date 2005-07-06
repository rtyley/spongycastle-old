package org.bouncycastle.openpgp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.TrustPacket;

/**
 *A PGP signature object.
 */
public class PGPSignature
{
    public static final int    BINARY_DOCUMENT = 0x00;
    public static final int    CANONICAL_TEXT_DOCUMENT = 0x01;
    public static final int    STAND_ALONE = 0x02;
    
    public static final int    DEFAULT_CERTIFICATION = 0x10;
    public static final int    NO_CERTIFICATION = 0x11;
    public static final int    CASUAL_CERTIFICATION = 0x12;
    public static final int    POSITIVE_CERTIFICATION = 0x13;
    
    public static final int    SUBKEY_BINDING = 0x18;
    public static final int    DIRECT_KEY = 0x1f;
    public static final int    KEY_REVOCATION = 0x20;
    public static final int    SUBKEY_REVOCATION = 0x28;
    public static final int    CERTIFICATION_REVOCATION = 0x30;
    public static final int    TIMESTAMP = 0x40;
    
    private SignaturePacket    sigPck;
    private Signature          sig;
    private int                signatureType;
    private TrustPacket        trustPck;
    
    PGPSignature(
        BCPGInputStream    pIn)
        throws IOException, PGPException
    {
        this((SignaturePacket)pIn.readPacket());
    }
    
    PGPSignature(
        SignaturePacket    sigPacket)
        throws PGPException
    {
        sigPck = sigPacket;
        signatureType = sigPck.getSignatureType();
        trustPck = null;
    }
    
    PGPSignature(
        SignaturePacket    sigPacket,
        TrustPacket        trustPacket)
        throws PGPException
    {
        this(sigPacket);
        
        this.trustPck = trustPacket;
    }
    
    private void getSig(
        String provider)
        throws PGPException
    {
        try
        {
            this.sig = Signature.getInstance(PGPUtil.getSignatureName(sigPck.getKeyAlgorithm(), sigPck.getHashAlgorithm()), provider);
        }
        catch (Exception e)
        {    
            throw new PGPException("can't set up signature object.", e);
        }
    }

    public void initVerify(
        PGPPublicKey    pubKey,
        String          provider)
        throws NoSuchProviderException, PGPException
    {    
        if (sig == null)
        {
            getSig(provider);
        }

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
    
    public boolean verify()
        throws PGPException, SignatureException
    {
        sig.update(this.getSignatureTrailer());
            
        return sig.verify(this.getSignature());
    }
    
    /**
     * Verify the signature as certifying the passed in public key as associated
     * with the passed in id.
     * 
     * @param id id the key was stored under
     * @param key the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws PGPException
     * @throws SignatureException
     */
    public boolean verifyCertification(
        String          id,
        PGPPublicKey    key)
        throws PGPException, SignatureException
    {
        byte[] keyBytes;
        try
        {
            keyBytes = key.publicPk.getEncodedContents();
        }
        catch (IOException e)
        {
            throw new PGPException("can't get encoding of public key", e);
        }
        
        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
            
        //
        // hash in the id
        //
        byte[]    idBytes = new byte[id.length()];
            
        for (int i = 0; i != idBytes.length; i++)
        {
            idBytes[i] = (byte)id.charAt(i);
        }
            
        this.update((byte)0xb4);
        this.update((byte)(idBytes.length >> 24));
        this.update((byte)(idBytes.length >> 16));
        this.update((byte)(idBytes.length >> 8));
        this.update((byte)(idBytes.length));
        this.update(idBytes);

        this.update(sigPck.getSignatureTrailer());
        
        return sig.verify(this.getSignature());
    }
    
    /**
     * Verify a certification for the passed in key against the passed in
     * master key.
     * 
     * @param masterKey the key we are verifying against.
     * @param pubKey the key we are verifying.
     * @return true if the certification is valid, false otherwise.
     * @throws SignatureException
     * @throws PGPException
     */
    public boolean verifyCertification(
        PGPPublicKey    masterKey,
        PGPPublicKey    pubKey) 
        throws SignatureException, PGPException
    {
        byte[]    keyBytes;
        
        try
        {
            keyBytes = masterKey.publicPk.getEncodedContents();
        }
        catch (IOException e)
        {
            throw new PGPException("exception preparing key.", e);
        }

        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
        
        try
        {
            keyBytes = pubKey.publicPk.getEncodedContents();
        }
        catch (IOException e)
        {
            throw new PGPException("exception preparing key.", e);
        }

        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
        
        this.update(sigPck.getSignatureTrailer());
        
        return sig.verify(this.getSignature());
    }
    
    /**
     * Verify a key certification, such as a revocation, for the passed in key.
     * 
     * @param pubKey the key we are checking.
     * @return true if the certification is valid, false otherwise.
     * @throws SignatureException
     * @throws PGPException
     */
    public boolean verifyCertification(
        PGPPublicKey    pubKey) 
        throws SignatureException, PGPException
    {
        if (this.getSignatureType() != KEY_REVOCATION
            && this.getSignatureType() != SUBKEY_REVOCATION)
        {
            throw new IllegalStateException("signature is not a key signature");
        }
        
        byte[]    keyBytes;
        
        try
        {
            keyBytes = pubKey.publicPk.getEncodedContents();
        }
        catch (IOException e)
        {
            throw new PGPException("exception preparing key.", e);
        }

        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
        
        this.update(sigPck.getSignatureTrailer());
        
        return sig.verify(this.getSignature());
    }
    
    public int getSignatureType()
    {
         return sigPck.getSignatureType();
    }
    
    /**
     * Return the id of the key that created the signature.
     * @return keyID of the signatures corresponding key.
     */
    public long getKeyID()
    {
         return sigPck.getKeyID();
    }
    
    /**
     * Return the creation time of the signature.
     * 
     * @return the signature creation time.
     */
    public Date getCreationTime()
    {
        return new Date(sigPck.getCreationTime());
    }
    
    public byte[] getSignatureTrailer()
    {
        return sigPck.getSignatureTrailer();
    }
    
    public PGPSignatureSubpacketVector getHashedSubPackets()
    {
        return new PGPSignatureSubpacketVector(sigPck.getHashedSubPackets());
    }
    
    public PGPSignatureSubpacketVector getUnhashedSubPackets()
    {
        return new PGPSignatureSubpacketVector(sigPck.getUnhashedSubPackets());
    }
    
    public byte[] getSignature()
        throws PGPException
    {
        MPInteger[]    sigValues = sigPck.getSignature();
        byte[]            signature;

        if (sigValues.length == 1)    // an RSA signature
        {
            byte[]    sBytes = sigValues[0].getValue().toByteArray();
    
            if (sBytes[0] == 0)
            {
                signature = new byte[sBytes.length - 1];
                System.arraycopy(sBytes, 1, signature, 0, signature.length);
            }
            else
            {
                signature = sBytes;
            }
        }
        else
        {
            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
            ASN1OutputStream         aOut = new ASN1OutputStream(bOut);
            
            try
            {
                ASN1EncodableVector     v = new ASN1EncodableVector();

                v.add(new DERInteger(sigValues[0].getValue()));
                v.add(new DERInteger(sigValues[1].getValue()));

                aOut.writeObject(new DERSequence(v));
            }
            catch (IOException e)
            {
                throw new PGPException("exception encoding DSA sig.", e);
            }
            
            signature = bOut.toByteArray();
        }
        
        return signature;
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

        out.writePacket(sigPck);
        if (trustPck != null)
        {
            out.writePacket(trustPck);
        }
    }
}
