package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.OnePassSignaturePacket;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.IssuerKeyID;
import org.bouncycastle.bcpg.sig.SignatureCreationTime;

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
    
    private byte            lastb;
    
    SignatureSubpacket[]    unhashed = new SignatureSubpacket[0];
    SignatureSubpacket[]    hashed = new SignatureSubpacket[0];
    
    /**
     * Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.
     *
     * @param keyAlgorithm keyAlgorithm to use for signing
     * @param hashAlgorithm algorithm to use for digest
     * @param provider provider to use for digest algorithm
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
        this(keyAlgorithm, provider, hashAlgorithm, provider);
    }

    /**
     * Create a generator for the passed in keyAlgorithm and hashAlgorithm codes.
     *
     * @param keyAlgorithm keyAlgorithm to use for signing
     * @param sigProvider provider to use for signature generation
     * @param hashAlgorithm algorithm to use for digest
     * @param provider provider to use for digest algorithm
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public PGPSignatureGenerator(
        int     keyAlgorithm,
        String  sigProvider,
        int     hashAlgorithm,
        String  provider)
        throws NoSuchAlgorithmException, NoSuchProviderException, PGPException
    {
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;

        dig = PGPUtil.getDigestInstance(PGPUtil.getDigestName(hashAlgorithm), sigProvider);
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
        if (hashedPcks == null)
        {
            hashed = new SignatureSubpacket[0];
            return;
        }
        
        hashed = hashedPcks.toSubpacketArray();
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
        SignatureSubpacket[]    hPkts, unhPkts;

        if (!packetPresent(hashed, SignatureSubpacketTags.CREATION_TIME))
        {
            hPkts = insertSubpacket(hashed, new SignatureCreationTime(false, new Date()));
        }
        else
        {
            hPkts = hashed;
        }
        
        if (!packetPresent(hashed, SignatureSubpacketTags.ISSUER_KEY_ID) && !packetPresent(unhashed, SignatureSubpacketTags.ISSUER_KEY_ID))
        {
            unhPkts = insertSubpacket(unhashed, new IssuerKeyID(false, privKey.getKeyID()));
        }
        else
        {
            unhPkts = unhashed;
        }
        
        try
        {
            sOut.write((byte)version);
            sOut.write((byte)signatureType);
            sOut.write((byte)keyAlgorithm);
            sOut.write((byte)hashAlgorithm);
            
            ByteArrayOutputStream    hOut = new ByteArrayOutputStream();
            
            for (int i = 0; i != hPkts.length; i++)
            {
                hPkts[i].encode(hOut);
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
        
        return new PGPSignature(new SignaturePacket(signatureType, privKey.getKeyID(), keyAlgorithm, hashAlgorithm, hPkts, unhPkts, fingerPrint, sigValues));
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

    private boolean packetPresent(
        SignatureSubpacket[] packets,
        int type)
    {
        for (int i = 0; i != packets.length; i++)
        {
            if (packets[i].getType() == type)
            {
                return true;
            }
        }

        return false;
    }

    private SignatureSubpacket[] insertSubpacket(
        SignatureSubpacket[] packets,
        SignatureSubpacket subpacket)
    {
        SignatureSubpacket[] tmp = new SignatureSubpacket[packets.length + 1];

        tmp[0] = subpacket;
        System.arraycopy(packets, 0, tmp, 1, packets.length);

        return tmp;
    }
}
