package org.bouncycastle.openpgp;

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

import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;
import org.bouncycastle.util.encoders.Hex;

/**
 * Generator for PGP Signatures.
 */
public class PGPSignatureGenerator
{
    private int             keyAlgorithm;
    private int             hashAlgorithm;
    private PGPPrivateKey   privKey;
    private Signature       sig;
    private MessageDigest   dig;
    private int             signatureType;
    private boolean         creationTimeFound;
    private boolean         issuerKeyIDFound;
    
    private byte            lastb;
    
    SignatureSubpacket[]    unhashed = new SignatureSubpacket[0];
    SignatureSubpacket[]    hashed = new SignatureSubpacket[2];
    
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
    public PGPSignatureGenerator(
        int     keyAlgorithm,
        int     hashAlgorithm,
        String  provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, PGPException
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
        int             signatureType,
        PGPPrivateKey   key)
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
        byte[]    b) 
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
    
    public void setHashedSubpackets(
        PGPSignatureSubpacketVector    hashedPcks)
    {
        creationTimeFound = false;
        issuerKeyIDFound = false;
    
        if (hashedPcks == null)
        {
            hashed = new SignatureSubpacket[2];
            return;
        }
        
        SignatureSubpacket[]    tmp = hashedPcks.toSubpacketArray();
        
    
        for (int i = 0; i != tmp.length; i++)
        {
            if (tmp[i].getType() == SignatureSubpacketTags.CREATION_TIME)
            {
                creationTimeFound = true;
            }
            else if(tmp[i].getType() == SignatureSubpacketTags.ISSUER_KEY_ID)
            {
                issuerKeyIDFound = true;
            }
        }
        
        if (creationTimeFound && issuerKeyIDFound)
        {
            hashed = tmp;
        }
        else if (creationTimeFound || issuerKeyIDFound)
        {
            hashed = new SignatureSubpacket[tmp.length + 1];
            System.arraycopy(tmp, 0, hashed, 1, tmp.length);
        }
        else
        {
            hashed = new SignatureSubpacket[tmp.length + 2];
            System.arraycopy(tmp, 0, hashed, 2, tmp.length);
        }
    }
    
    public void setUnhashedSubpackets(
        PGPSignatureSubpacketVector    unhashedPcks)
    {
        if (unhashedPcks == null)
        {
            unhashed = new SignatureSubpacket[0];
            return;
        }
        
        unhashed = unhashedPcks.toSubpacketArray();
    }
    
    /**
     * Return the one pass header associated with the current signature.
     * 
     * @param isNested
     * @return PGPOnePassSignature
     * @throws PGPException
     */
    public PGPOnePassSignature generateOnePassVersion(
        boolean    isNested)
        throws PGPException
    {
        return new PGPOnePassSignature(new OnePassSignaturePacket(signatureType, hashAlgorithm, keyAlgorithm, privKey.getKeyID(), isNested));
    }
    
    /**
     * Return a signature object containing the current signature state.
     * 
     * @return PGPSignature
     * @throws PGPException
     * @throws SignatureException
     */
    public PGPSignature generate()
        throws PGPException, SignatureException
    {
        MPInteger[]             sigValues;
        int                     version = 4;
        ByteArrayOutputStream   sOut = new ByteArrayOutputStream();
        
        int    index = 0;
        
        if (!creationTimeFound)
        {
            hashed[index++] = new SignatureCreationTime(false, new Date());
        }
        
        if (!issuerKeyIDFound)
        {
            hashed[index++] = new IssuerKeyID(false, privKey.getKeyID());
        }
        
        try
        {
            sOut.write((byte)version);
            sOut.write((byte)signatureType);
            sOut.write((byte)keyAlgorithm);
            sOut.write((byte)hashAlgorithm);
            
            ByteArrayOutputStream    hOut = new ByteArrayOutputStream();
            
            for (int i = 0; i != hashed.length; i++)
            {
                hashed[i].encode(hOut);
            }
                
            byte[]                            data = hOut.toByteArray();
    
            sOut.write((byte)(data.length >> 8));
            sOut.write((byte)data.length);
            sOut.write(data);
        }
        catch (IOException e)
        {
            throw new PGPException("exception encoding hashed data.", e);
        }
        
        byte[]    hData = sOut.toByteArray();
        
        sOut.write((byte)version);
        sOut.write((byte)0xff);
        sOut.write((byte)(hData.length >> 24));
        sOut.write((byte)(hData.length >> 16));
        sOut.write((byte)(hData.length >> 8));
        sOut.write((byte)(hData.length));
        
        byte[]    trailer = sOut.toByteArray();
        
        sig.update(trailer);
        dig.update(trailer);

        if (keyAlgorithm == PublicKeyAlgorithmTags.RSA_SIGN
            || keyAlgorithm == PublicKeyAlgorithmTags.RSA_GENERAL)    // an RSA signature
        {
            sigValues = new MPInteger[1];
            sigValues[0] = new MPInteger(new BigInteger(1, sig.sign()));
        }
        else
        {   
            sigValues = PGPUtil.dsaSigToMpi(sig.sign());
        }
        
        byte[]                        digest = dig.digest();
        byte[]                        fingerPrint = new byte[2];

        fingerPrint[0] = digest[0];
        fingerPrint[1] = digest[1];
        
        return new PGPSignature(new SignaturePacket(signatureType, privKey.getKeyID(), keyAlgorithm, hashAlgorithm, hashed, unhashed, fingerPrint, sigValues));
    }
    
    /**
     * Generate a certification for the passed in id and key.
     * 
     * @param id the id we are certifying against the public key.
     * @param pubKey the key we are certifying against the id.
     * @return the certification.
     * @throws SignatureException
     * @throws PGPException
     */
    public PGPSignature generateCertification(
        String          id,
        PGPPublicKey    pubKey) 
        throws SignatureException, PGPException
    {
        byte[]    keyBytes = getEncodedPublicKey(pubKey);

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
        
        return this.generate();
    }
    
    /**
     * Generate a certification for the passed in key against the passed in
     * master key.
     * 
     * @param masterKey the key we are certifying against.
     * @param pubKey the key we are certifying.
     * @return the certification.
     * @throws SignatureException
     * @throws PGPException
     */
    public PGPSignature generateCertification(
        PGPPublicKey    masterKey,
        PGPPublicKey    pubKey) 
        throws SignatureException, PGPException
    {
        byte[]    keyBytes = getEncodedPublicKey(masterKey);

        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
        
        keyBytes = getEncodedPublicKey(pubKey);

        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
        
        return this.generate();
    }
    
    /**
     * Generate a certification, such as a revocation, for the passed in key.
     * 
     * @param pubKey the key we are certifying.
     * @return the certification.
     * @throws SignatureException
     * @throws PGPException
     */
    public PGPSignature generateCertification(
        PGPPublicKey    pubKey)
        throws SignatureException, PGPException
    {
        byte[]    keyBytes = getEncodedPublicKey(pubKey);

        this.update((byte)0x99);
        this.update((byte)(keyBytes.length >> 8));
        this.update((byte)(keyBytes.length));
        this.update(keyBytes);
        
        return this.generate();
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
