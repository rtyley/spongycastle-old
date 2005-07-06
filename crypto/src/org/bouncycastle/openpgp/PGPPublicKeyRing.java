package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.SignaturePacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserIDPacket;

/**
 * general class to hold a collection of PGP Public Keys.
 */
public class PGPPublicKeyRing
{
    ArrayList            keys = new ArrayList();
    
    public PGPPublicKeyRing(
        byte[]    encoding)
        throws IOException
    {
        this(new ByteArrayInputStream(encoding));
    }
    
    /**
     * @param pubKeys
     */
    PGPPublicKeyRing(
        ArrayList pubKeys)
    {
        this.keys = pubKeys;
    }

    public PGPPublicKeyRing(
        InputStream    in)
        throws IOException
    {    
        BCPGInputStream    pIn;
        
        if (in instanceof BCPGInputStream)
        {
            pIn = (BCPGInputStream)in;
        }
        else
        {
            pIn = new BCPGInputStream(in);
        }
        
        PublicKeyPacket   pubPk;
        TrustPacket       trustPk;
        ArrayList         keySigs = new ArrayList();
        ArrayList         ids = new ArrayList();
        ArrayList         idTrust = new ArrayList();
        ArrayList         idSigs = new ArrayList();
    
        pubPk = (PublicKeyPacket)pIn.readPacket();
        trustPk = null;
        if (pIn.nextPacketTag() == PacketTags.TRUST)
        {
            trustPk = (TrustPacket)pIn.readPacket();
        }
        
        //
        // direct signatures and revocations
        //
        while (pIn.nextPacketTag() == PacketTags.SIGNATURE)
        {
            try
            {
                SignaturePacket    s = (SignaturePacket)pIn.readPacket();
                
                if (pIn.nextPacketTag() == PacketTags.TRUST)
                {
                    keySigs.add(new PGPSignature(s, (TrustPacket)pIn.readPacket()));
                }
                else
                {
                    keySigs.add(new PGPSignature(s));
                }
            }
            catch (PGPException e)
            {
                throw new IOException("can't create signature object: " + e.getMessage() + ", cause: " + e.getUnderlyingException().toString());
            }
            

        }
        
        while (pIn.nextPacketTag() == PacketTags.USER_ID
            || pIn.nextPacketTag() == PacketTags.USER_ATTRIBUTE)
        {
            Object    obj = pIn.readPacket();
            
            if (obj instanceof UserIDPacket)
            {
                UserIDPacket    id = (UserIDPacket)obj;
                ids.add(id.getID());
            }
            else
            {
                UserAttributePacket    user = (UserAttributePacket)obj;
                ids.add(new PGPUserAttributeSubpacketVector(user.getSubpackets()));
            }
            
            if (pIn.nextPacketTag() == PacketTags.TRUST)
            {
                idTrust.add(pIn.readPacket());
            }
            else
            {
                idTrust.add(null);
            }
            
            ArrayList        sigList = new ArrayList();
            
            idSigs.add(sigList);

            while (pIn.nextPacketTag() == PacketTags.SIGNATURE)
            {
                try
                {
                    SignaturePacket    s = (SignaturePacket)pIn.readPacket();

                    if (pIn.nextPacketTag() == PacketTags.TRUST)
                    {
                        sigList.add(new PGPSignature(s, (TrustPacket)pIn.readPacket()));
                    }
                    else
                    {
                        sigList.add(new PGPSignature(s));
                    }
                }
                catch (PGPException e)
                {
                    throw new IOException("can't create signature object: " + e.getMessage() + ", cause: " + e.getUnderlyingException().toString());
                }
            }
        }
        
        keys.add(new PGPPublicKey(pubPk, trustPk, keySigs, ids, idTrust, idSigs));

        while (pIn.nextPacketTag() == PacketTags.PUBLIC_SUBKEY)
        {
            PublicKeyPacket    pk = (PublicKeyPacket)pIn.readPacket();
            TrustPacket        kTrust = null;
            
            if (pIn.nextPacketTag() == PacketTags.TRUST)
            {
                kTrust = (TrustPacket)pIn.readPacket();
            }

            ArrayList    sigList = new ArrayList();
            
            try
            {
                //
                // PGP 8 actually leaves out the signature.
                //
                while (pIn.nextPacketTag() == PacketTags.SIGNATURE)
                {
                    SignaturePacket    s = (SignaturePacket)pIn.readPacket();
    
                    if (pIn.nextPacketTag() == PacketTags.TRUST)
                    {
                        sigList.add(new PGPSignature(s, (TrustPacket)pIn.readPacket()));
                    }
                    else
                    {
                        sigList.add(new PGPSignature(s));
                    }
                }
            }
            catch (PGPException e)
            {
                throw new IOException("can't create signature object: " + e.getMessage() + ", cause: " + e.getUnderlyingException().toString());
            }

            keys.add(new PGPPublicKey(pk, kTrust, sigList));
        }
    }

    /**
     * Return the first public key in the ring.
     * 
     * @return PGPPublicKey
     */
    public PGPPublicKey getPublicKey()
    {
        return (PGPPublicKey)keys.get(0);
    }
    
    /**
     * Return the public key refered to by the passed in keyID if it
     * is present.
     * 
     * @param keyID
     * @return PGPPublicKey
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public PGPPublicKey getPublicKey(
        long        keyID)
        throws PGPException
    {    
        for (int i = 0; i != keys.size(); i++)
        {
            PGPPublicKey    k = (PGPPublicKey)keys.get(i);
            
            if (keyID == k.getKeyID())
            {
                return k;
            }
        }
    
        return null;
    }
    
    /**
     * Return an iterator containing all the public keys.
     * 
     * @return Iterator
     */
    public Iterator getPublicKeys()
    {
        return keys.iterator();
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
            PGPPublicKey    k = (PGPPublicKey)keys.get(i);
            
            k.encode(outStream);
        }
    }
    
    /**
     * Returns a new key ring with the publick key passed in
     * either added or replacing an existing one.
     * 
     * @param pubRing the public key ring to be modified
     * @param pubKey the public key to be added.
     * @return a new keyRing
     */
    public static PGPPublicKeyRing insertPublicKey(
        PGPPublicKeyRing  pubRing,
        PGPPublicKey      pubKey)
    {
        ArrayList  keys = new ArrayList(pubRing.keys);
        boolean    found = false;
        
        for (int i = 0; i != keys.size();i++)
        {
            PGPPublicKey   key = (PGPPublicKey)keys.get(i);
            
            if (key.getKeyID() == pubKey.getKeyID())
            {
                found = true;
                keys.set(i, pubKey);
            }
        }
        
        if (!found)
        {
            keys.add(pubKey);
        }
        
        return new PGPPublicKeyRing(keys);
    }
    
    /**
     * Returns a new key ring with the publick key passed in
     * removed from the key ring.
     * 
     * @param pubRing the public key ring to be modified
     * @param pubKey the public key to be added.
     * @return a new keyRing, null if pubKey is not found.
     */
    public static PGPPublicKeyRing removePublicKey(
        PGPPublicKeyRing  pubRing,
        PGPPublicKey      pubKey)
    {
        ArrayList  keys = new ArrayList(pubRing.keys);
        boolean    found = false;
        
        for (int i = 0; i < keys.size();i++)
        {
            PGPPublicKey   key = (PGPPublicKey)keys.get(i);
            
            if (key.getKeyID() == pubKey.getKeyID())
            {
                found = true;
                keys.remove(i);
            }
        }
        
        if (!found)
        {
            return null;
        }
        
        return new PGPPublicKeyRing(keys);
    }
}
