package org.spongycastle.openpgp;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.bcpg.*;
import org.spongycastle.util.BigIntegers;
import org.spongycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.Provider;
import java.util.Date;

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
    public static final int    PRIMARYKEY_BINDING = 0x19;
    public static final int    DIRECT_KEY = 0x1f;
    public static final int    KEY_REVOCATION = 0x20;
    public static final int    SUBKEY_REVOCATION = 0x28;
    public static final int    CERTIFICATION_REVOCATION = 0x30;
    public static final int    TIMESTAMP = 0x40;
    
    private SignaturePacket    sigPck;
    private Signature          sig;
    private int                signatureType;
    private TrustPacket        trustPck;
    
    private byte               lastb;
    
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
        Provider provider)
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

    /**
     * Return the OpenPGP version number for this signature.
     * 
     * @return signature version number.
     */
    public int getVersion()
    {
        return sigPck.getVersion();
    }
    
    /**
     * Return the key algorithm associated with this signature.
     * @return signature key algorithm.
     */
    public int getKeyAlgorithm()
    {
        return sigPck.getKeyAlgorithm();
    }
    
    /**
     * Return the hash algorithm associated with this signature.
     * @return signature hash algorithm.
     */
    public int getHashAlgorithm()
    {
        return sigPck.getHashAlgorithm();
    }

    public void initVerify(
        PGPPublicKey    pubKey,
        String          provider)
        throws NoSuchProviderException, PGPException
    {
        initVerify(pubKey, PGPUtil.getProvider(provider));
    }

    public void initVerify(
        PGPPublicKey    pubKey,
        Provider        provider)
        throws PGPException
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
        
        lastb = 0;
    }
        
    public void update(
        byte    b)
        throws SignatureException
    {
        if (signatureType == PGPSignature.CANONICAL_TEXT_DOCUMENT)
        {
            if (b == '\r')
            {
                sig.update((byte)'\r');
                sig.update((byte)'\n');
            }
            else if (b == '\n')
            {
                if (lastb != '\r')
                {
                    sig.update((byte)'\r');
                    sig.update((byte)'\n');
                }
            }
            else
            {
                sig.update(b);
            }

            lastb = b;
        }
        else
        {
            sig.update(b);
        }
    }
        
    public void update(
        byte[]    bytes)
        throws SignatureException
    {
        this.update(bytes, 0, bytes.length);
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


    private void updateWithIdData(int header, byte[] idBytes)
        throws SignatureException
    {
        this.update((byte)header);
        this.update((byte)(idBytes.length >> 24));
        this.update((byte)(idBytes.length >> 16));
        this.update((byte)(idBytes.length >> 8));
        this.update((byte)(idBytes.length));
        this.update(idBytes);
    }
    
    private void updateWithPublicKey(PGPPublicKey key)
        throws PGPException, SignatureException
    {
        byte[] keyBytes = getEncodedPublicKey(key);

        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
    }

    /**
     * Verify the signature as certifying the passed in public key as associated
     * with the passed in user attributes.
     *
     * @param userAttributes user attributes the key was stored under
     * @param key the key to be verified.
     * @return true if the signature matches, false otherwise.
     * @throws PGPException
     * @throws SignatureException
     */
    public boolean verifyCertification(
        PGPUserAttributeSubpacketVector userAttributes,
        PGPPublicKey    key)
        throws PGPException, SignatureException
    {
        updateWithPublicKey(key);

        //
        // hash in the userAttributes
        //
        try
        {
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            UserAttributeSubpacket[] packets = userAttributes.toSubpacketArray();
            for (int i = 0; i != packets.length; i++)
            {
                packets[i].encode(bOut);
            }
            updateWithIdData(0xd1, bOut.toByteArray());
        }
        catch (IOException e)
        {
            throw new PGPException("cannot encode subpacket array", e);
        }

        this.update(sigPck.getSignatureTrailer());

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
        updateWithPublicKey(key);
            
        //
        // hash in the id
        //
        updateWithIdData(0xb4, Strings.toByteArray(id));

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
        updateWithPublicKey(masterKey);
        updateWithPublicKey(pubKey);
        
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

        updateWithPublicKey(pubKey);
        
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

    /**
     * Return true if the signature has either hashed or unhashed subpackets.
     * 
     * @return true if either hashed or unhashed subpackets are present, false otherwise.
     */
    public boolean hasSubpackets()
    {
        return sigPck.getHashedSubPackets() != null || sigPck.getUnhashedSubPackets() != null;
    }

    public PGPSignatureSubpacketVector getHashedSubPackets()
    {
        return createSubpacketVector(sigPck.getHashedSubPackets());
    }

    public PGPSignatureSubpacketVector getUnhashedSubPackets()
    {
        return createSubpacketVector(sigPck.getUnhashedSubPackets());
    }
    
    private PGPSignatureSubpacketVector createSubpacketVector(SignatureSubpacket[] pcks)
    {
        if (pcks != null)
        {
            return new PGPSignatureSubpacketVector(pcks);
        }
        
        return null;
    }
    
    public byte[] getSignature()
        throws PGPException
    {
        MPInteger[]    sigValues = sigPck.getSignature();
        byte[]         signature;

        if (sigValues != null)
        {
            if (sigValues.length == 1)    // an RSA signature
            {
                signature = BigIntegers.asUnsignedByteArray(sigValues[0].getValue());
            }
            else
            {
                try
                {
                    ASN1EncodableVector v = new ASN1EncodableVector();
                    v.add(new DERInteger(sigValues[0].getValue()));
                    v.add(new DERInteger(sigValues[1].getValue()));

                    signature = new DERSequence(v).getEncoded();
                }
                catch (IOException e)
                {
                    throw new PGPException("exception encoding DSA sig.", e);
                }
            }
        }
        else
        {
            signature = sigPck.getSignatureBytes();
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
    
    private byte[] getEncodedPublicKey(
        PGPPublicKey pubKey) 
        throws PGPException
    {
        byte[]    keyBytes;
        
        try
        {
            keyBytes = pubKey.publicPk.getEncodedContents();
        }
        catch (IOException e)
        {
            throw new PGPException("exception preparing key.", e);
        }
        
        return keyBytes;
    }
}
