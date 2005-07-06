package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;

import org.bouncycastle.bcpg.*;

/**
 * Holder for a collection of PGP secret keys.
 */
public class PGPSecretKeyRing
{    
    ArrayList            keys = new ArrayList();
    
    /**
     * @param keys
     */
    PGPSecretKeyRing(ArrayList keys)
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
        BCPGInputStream    pIn;
        
        if (in instanceof BCPGInputStream)
        {
            pIn = (BCPGInputStream)in;
        }
        else
        {
            pIn = new BCPGInputStream(in);
        }
        
        SecretKeyPacket secret = (SecretKeyPacket)pIn.readPacket();
        TrustPacket     trust = null;
        ArrayList       keySigs = new ArrayList();
        ArrayList       ids = new ArrayList();
        ArrayList       idTrusts = new ArrayList();
        ArrayList       idSigs = new ArrayList();
        MessageDigest   sha;
        
        try
        {
            sha = MessageDigest.getInstance("SHA1");
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new IOException("can't find SHA1 digest");
        }
        
        //
        // ignore GPG comment packets if found.
        //
        while (pIn.nextPacketTag() == PacketTags.EXPERIMENTAL_2)
        {
            pIn.readPacket();
        }
        
        if (pIn.nextPacketTag() == PacketTags.TRUST)
        {
            trust = (TrustPacket)pIn.readPacket(); // ignore for the moment
        }
        
        //
        // revocation and direct signatures
        //
        while (pIn.nextPacketTag() == PacketTags.SIGNATURE)
        {
            try
            {
                keySigs.add(new PGPSignature(pIn));
            }
            catch (PGPException e)
            {
                throw new IOException("can't create signature object: " + e.getMessage() + ", cause: " + e.getUnderlyingException().toString());
            }
        }
        
        while (pIn.nextPacketTag() == PacketTags.USER_ID
            || pIn.nextPacketTag() == PacketTags.USER_ATTRIBUTE)
        {
            Object                obj = pIn.readPacket();
            ArrayList            sigList = new ArrayList();
            
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
                idTrusts.add(pIn.readPacket());
            }
            else
            {
                idTrusts.add(null);
            }
        
            idSigs.add(sigList);
            
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
        
        keys.add(new PGPSecretKey(secret, trust, sha, keySigs, ids, idTrusts, idSigs));

        while (pIn.nextPacketTag() == PacketTags.SECRET_SUBKEY)
        {
            SecretSubkeyPacket    sub = (SecretSubkeyPacket)pIn.readPacket();
            TrustPacket                subTrust = null;
            ArrayList                    sigList = new ArrayList();
            
            //
            // ignore GPG comment packets if found.
            //
            while (pIn.nextPacketTag() == PacketTags.EXPERIMENTAL_2)
            {
                pIn.readPacket();
            }

            if (pIn.nextPacketTag() == PacketTags.TRUST)
            {
                subTrust = (TrustPacket)pIn.readPacket();
            }
            
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
            
            keys.add(new PGPSecretKey(sub, subTrust, sha, sigList));
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
        return keys.iterator();
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
}
