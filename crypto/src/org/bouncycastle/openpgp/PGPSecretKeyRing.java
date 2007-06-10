package org.bouncycastle.openpgp;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.bcpg.TrustPacket;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * Holder for a collection of PGP secret keys.
 */
public class PGPSecretKeyRing
    extends PGPKeyRing
{    
    final List keys;
    
    PGPSecretKeyRing(List keys)
    {
        this.keys = keys;
    }

    public PGPSecretKeyRing(
        byte[]    encoding)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding));
    }
    
    public PGPSecretKeyRing(
        InputStream    in)
        throws IOException, PGPException
    {
        this.keys = new ArrayList();

        BCPGInputStream pIn = wrap(in);

        int initialTag = pIn.nextPacketTag();
        if (initialTag != PacketTags.SECRET_KEY && initialTag != PacketTags.SECRET_SUBKEY)
        {
            throw new IOException(
                "secret key ring doesn't start with secret key tag: " +
                "tag 0x" + Integer.toHexString(initialTag));
        }

        SecretKeyPacket secret = (SecretKeyPacket)pIn.readPacket();

        //
        // ignore GPG comment packets if found.
        //
        while (pIn.nextPacketTag() == PacketTags.EXPERIMENTAL_2)
        {
            pIn.readPacket();
        }
        
        TrustPacket trust = readOptionalTrustPacket(pIn);

        // revocation and direct signatures
        List keySigs = readSignaturesAndTrust(pIn);

        List ids = new ArrayList();
        List idTrusts = new ArrayList();
        List idSigs = new ArrayList();
        readUserIDs(pIn, ids, idTrusts, idSigs);

        keys.add(new PGPSecretKey(secret, trust, keySigs, ids, idTrusts, idSigs));


        // Read subkeys
        while (pIn.nextPacketTag() == PacketTags.SECRET_SUBKEY)
        {
            SecretSubkeyPacket    sub = (SecretSubkeyPacket)pIn.readPacket();

            //
            // ignore GPG comment packets if found.
            //
            while (pIn.nextPacketTag() == PacketTags.EXPERIMENTAL_2)
            {
                pIn.readPacket();
            }

            TrustPacket subTrust = readOptionalTrustPacket(pIn);
            List        sigList = readSignaturesAndTrust(pIn);

            keys.add(new PGPSecretKey(sub, subTrust, sigList));
        }
    }

    /**
     * Return the public key for the master key.
     * 
     * @return PGPPublicKey
     */
    public PGPPublicKey getPublicKey()
    {
        return ((PGPSecretKey)keys.get(0)).getPublicKey();
    }

    /**
     * Return the master private key.
     * 
     * @return PGPSecretKey
     */
    public PGPSecretKey getSecretKey()
    {
        return ((PGPSecretKey)keys.get(0));
    }
    
    /**
     * Return an iterator containing all the secret keys.
     * 
     * @return Iterator
     */
    public Iterator getSecretKeys()
    {
        return Collections.unmodifiableList(keys).iterator();
    }
    
    public PGPSecretKey getSecretKey(
        long        keyId)
    {    
        for (int i = 0; i != keys.size(); i++)
        {
            PGPSecretKey    k = (PGPSecretKey)keys.get(i);
            
            if (keyId == k.getKeyID())
            {
                return k;
            }
        }
    
        return null;
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
        for (int i = 0; i != keys.size(); i++)
        {
            PGPSecretKey    k = (PGPSecretKey)keys.get(i);
            
            k.encode(outStream);
        }
    }
    
    /**
     * Returns a new key ring with the secret key passed in either added or
     * replacing an existing one with the same key ID.
     * 
     * @param secRing the secret key ring to be modified.
     * @param secKey the secret key to be added.
     * @return a new secret key ring.
     */
    public static PGPSecretKeyRing insertSecretKey(
        PGPSecretKeyRing  secRing,
        PGPSecretKey      secKey)
    {
        List       keys = new ArrayList(secRing.keys);
        boolean    found = false;
        
        for (int i = 0; i != keys.size();i++)
        {
            PGPSecretKey   key = (PGPSecretKey)keys.get(i);
            
            if (key.getKeyID() == secKey.getKeyID())
            {
                found = true;
                keys.set(i, secKey);
            }
        }
        
        if (!found)
        {
            keys.add(secKey);
        }
        
        return new PGPSecretKeyRing(keys);
    }
    
    /**
     * Returns a new key ring with the secret key passed in removed from the
     * key ring.
     * 
     * @param secRing the secret key ring to be modified.
     * @param secKey the secret key to be removed.
     * @return a new secret key ring, or null if secKey is not found.
     */
    public static PGPSecretKeyRing removeSecretKey(
        PGPSecretKeyRing  secRing,
        PGPSecretKey      secKey)
    {
        List       keys = new ArrayList(secRing.keys);
        boolean    found = false;
        
        for (int i = 0; i < keys.size();i++)
        {
            PGPSecretKey   key = (PGPSecretKey)keys.get(i);
            
            if (key.getKeyID() == secKey.getKeyID())
            {
                found = true;
                keys.remove(i);
            }
        }
        
        if (!found)
        {
            return null;
        }
        
        return new PGPSecretKeyRing(keys);
    }
}
