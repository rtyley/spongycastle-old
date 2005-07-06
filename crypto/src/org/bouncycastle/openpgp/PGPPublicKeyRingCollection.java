package org.bouncycastle.openpgp;

import java.io.*;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.bcpg.BCPGOutputStream;

/**
 * Often a PGP key ring file is made up of a succession of master/sub-key key rings.
 * If you want to read an entire public key file in one hit this is the class for you.
 */
public class PGPPublicKeyRingCollection 
{
    private HashMap    pubRings = new HashMap();
    private ArrayList  order = new ArrayList();
    
    private PGPPublicKeyRingCollection(
        HashMap     pubRings,
        ArrayList   order)
    {
        this.pubRings = pubRings;
        this.order = order;
    }
    
    public PGPPublicKeyRingCollection(
        byte[]    encoding)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding));
    }
    
    public PGPPublicKeyRingCollection(
        InputStream    in)
        throws IOException, PGPException
    {
        PGPObjectFactory    pgpFact = new PGPObjectFactory(in);
        PGPPublicKeyRing    pgpPub = null;
        
        while ((pgpPub = (PGPPublicKeyRing)pgpFact.nextObject()) != null)
        {
            Long    key = new Long(pgpPub.getPublicKey().getKeyID());
            
            pubRings.put(key, pgpPub);
            order.add(key);
        }
    }
    
    public PGPPublicKeyRingCollection(
        Collection    collection)
        throws IOException, PGPException
    {
        Iterator                    it = collection.iterator();
        
        while (it.hasNext())
        {
            PGPPublicKeyRing  pgpPub = (PGPPublicKeyRing)it.next();
            
            Long              key = new Long(pgpPub.getPublicKey().getKeyID());
            
            pubRings.put(key, pgpPub);
            order.add(key);
        }
    }
    
    /**
     * Return the number of rings in this collection.
     * 
     * @return size of the collection
     */
    public int size()
    {
        return order.size();
    }
    
    /**
     * return the public key rings making up this collection.
     */
    public Iterator getKeyRings()
    {
        return pubRings.values().iterator();
    }
    
    /**
     * Return an iterator of the key rings associated with the passed in userID.
     * <p>
     * 
     * @param userID the user ID to be matched.
     * @param matchPartial if true userID need only be a substring of an actual ID string to match.
     * @return an iterator (possibly empty) of key rings which matched.
     * @throws PGPException
     */
    public Iterator getKeyRings(
        String    userID,
        boolean   matchPartial) 
        throws PGPException
    {
        Iterator    it = this.getKeyRings();
        List        rings = new ArrayList();
        
        while (it.hasNext())
        {
            PGPPublicKeyRing pubRing = (PGPPublicKeyRing)it.next();
            Iterator         uIt = pubRing.getPublicKey().getUserIDs();
            
            while (uIt.hasNext())
            {
                if (matchPartial)
                {
                    if (((String)uIt.next()).indexOf(userID) > -1)
                    {
                        rings.add(pubRing);
                    }
                }
                else
                {
                    if (uIt.next().equals(userID))
                    {
                        rings.add(pubRing);
                    }
                }
            }
        }
    
        return rings.iterator();
    }
    
    /**
     * Return an iterator of the key rings associated with the passed in userID.
     * 
     * @param userID the user ID to be matched.
     * @return an iterator (possibly empty) of key rings which matched.
     * @throws PGPException
     */
    public Iterator getKeyRings(
        String    userID) 
        throws PGPException
    {   
        return getKeyRings(userID, false);
    }
    
    /**
     * Return the PGP public key associated with the given key id.
     * 
     * @param keyID
     * @return the PGP public key
     * @throws PGPException
     */
    public PGPPublicKey getPublicKey(
        long        keyID) 
        throws PGPException
    {    
        Iterator    it = this.getKeyRings();
        
        while (it.hasNext())
        {
            PGPPublicKeyRing    pubRing = (PGPPublicKeyRing)it.next();
            PGPPublicKey        pub = pubRing.getPublicKey(keyID);
            
            if (pub != null)
            {
                return pub;
            }
        }
    
        return null;
    }
    
    /**
     * Return the public key ring which contains the key referred to by keyID.
     * 
     * @param keyID
     * @return the public key ring
     * @throws PGPException
     */
    public PGPPublicKeyRing getPublicKeyRing(
        long    keyID) 
        throws PGPException
    {
        Long    id = new Long(keyID);
        
        if (pubRings.containsKey(id))
        {
            return (PGPPublicKeyRing)pubRings.get(id);
        }
        
        Iterator    it = this.getKeyRings();
        
        while (it.hasNext())
        {
            PGPPublicKeyRing    pubRing = (PGPPublicKeyRing)it.next();
            PGPPublicKey        pub = pubRing.getPublicKey(keyID);
            
            if (pub != null)
            {
                return pubRing;
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
        BCPGOutputStream    out;
        
        if (outStream instanceof BCPGOutputStream)
        {
            out = (BCPGOutputStream)outStream;
        }
        else
        {
            out = new BCPGOutputStream(outStream);
        }

        Iterator    it = order.iterator();
        while (it.hasNext())
        {
            PGPPublicKeyRing    sr = (PGPPublicKeyRing)pubRings.get(it.next());
            
            sr.encode(out);
        }
    }
    
    
    /**
     * Return a new collection object containing the contents of the passed in collection and
     * the passed in public key ring.
     * 
     * @param ringCollection the collection the ring to be added to.
     * @param publicKeyRing the key ring to be added.
     * @return a new collection merging the current one with the passed in ring.
     * @exception IllegalArgumentException if the keyID for the passed in ring is already present.
     */
    public static PGPPublicKeyRingCollection addPublicKeyRing(
        PGPPublicKeyRingCollection ringCollection,
        PGPPublicKeyRing           publicKeyRing)
    {
        Long        key = new Long(publicKeyRing.getPublicKey().getKeyID());
        
        if (ringCollection.pubRings.containsKey(key))
        {
            throw new IllegalArgumentException("Collection already contains a key with a keyID for the passed in ring.");
        }
        
        HashMap     newPubRings = new HashMap(ringCollection.pubRings);
        ArrayList   newOrder = new ArrayList(ringCollection.order); 
        
        newPubRings.put(key, publicKeyRing);
        newOrder.add(key);
        
        return new PGPPublicKeyRingCollection(newPubRings, newOrder);
    }
    
    /**
     * Return a new collection object containing the contents of this collection with
     * the passed in public key ring removed.
     * 
     * @param ringCollection the collection the ring to be removed from.
     * @param publicKeyRing the key ring to be removed.
     * @return a new collection not containing the passed in ring.
     * @exception IllegalArgumentException if the keyID for the passed in ring not present.
     */
    public static PGPPublicKeyRingCollection removePublicKeyRing(
        PGPPublicKeyRingCollection ringCollection,
        PGPPublicKeyRing           publicKeyRing)
    {
        Long        key = new Long(publicKeyRing.getPublicKey().getKeyID());
        
        if (!ringCollection.pubRings.containsKey(key))
        {
            throw new IllegalArgumentException("Collection already contains a key with a keyID for the passed in ring.");
        }
        
        HashMap     newPubRings = new HashMap(ringCollection.pubRings);
        ArrayList   newOrder = new ArrayList(ringCollection.order); 
        
        newPubRings.remove(key);
        
        for (int i = 0; i < newOrder.size(); i++)
        {
            Long    r = (Long)newOrder.get(i);
            
            if (r.longValue() == key.longValue())
            {
                newOrder.remove(i);
                break;
            }
        }
        
        return new PGPPublicKeyRingCollection(newPubRings, newOrder);
    }
}
