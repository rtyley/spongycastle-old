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
 * If you want to read an entire secret key file in one hit this is the class for you.
 */
public class PGPSecretKeyRingCollection 
{
    private HashMap     secretRings = new HashMap();
    private ArrayList   order = new ArrayList();
    
    private PGPSecretKeyRingCollection(
        HashMap     secretRings,
        ArrayList   order)
    {
        this.secretRings = secretRings;
        this.order = order;
    }
    
    public PGPSecretKeyRingCollection(
        byte[]    encoding)
        throws IOException, PGPException
    {
        this(new ByteArrayInputStream(encoding));
    }
    
    public PGPSecretKeyRingCollection(
        InputStream    in)
        throws IOException, PGPException
    {
        PGPObjectFactory    pgpFact = new PGPObjectFactory(in);
        Object                        obj = null;

        while ((obj = pgpFact.nextObject()) != null)
        {
            if (!(obj instanceof PGPSecretKeyRing))
            {
                throw new IOException(obj.getClass().getName() + " found where PGPSecretKeyRingExpected");
            }
            
            PGPSecretKeyRing    pgpSecret = (PGPSecretKeyRing)obj;
            Long                key = new Long(pgpSecret.getPublicKey().getKeyID());
            
            secretRings.put(key, pgpSecret);
            order.add(key);
        }
    }
    
    public PGPSecretKeyRingCollection(
        Collection    collection)
        throws IOException, PGPException
    {
        Iterator                it = collection.iterator();

        while (it.hasNext())
        {
            PGPSecretKeyRing    pgpSecret = (PGPSecretKeyRing)it.next();
            Long                key = new Long(pgpSecret.getPublicKey().getKeyID());
            
            secretRings.put(key, pgpSecret);
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
     * return the secret key rings making up this collection.
     */
    public Iterator getKeyRings()
    {
        return secretRings.values().iterator();
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
            PGPSecretKeyRing secRing = (PGPSecretKeyRing)it.next();
            Iterator         uIt = secRing.getSecretKey().getUserIDs();
            
            while (uIt.hasNext())
            {
                if (matchPartial)
                {
                    if (((String)uIt.next()).indexOf(userID) > -1)
                    {
                        rings.add(secRing);
                    }
                }
                else
                {
                    if (uIt.next().equals(userID))
                    {
                        rings.add(secRing);
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
     * Return the PGP secret key associated with the given key id.
     * 
     * @param keyID
     * @return the secret key
     * @throws PGPException
     */
    public PGPSecretKey getSecretKey(
        long        keyID) 
        throws PGPException
    {    
        Iterator    it = this.getKeyRings();
        
        while (it.hasNext())
        {
            PGPSecretKeyRing    secRing = (PGPSecretKeyRing)it.next();
            PGPSecretKey        sec =secRing.getSecretKey(keyID);
            
            if (sec != null)
            {
                return sec;
            }
        }
    
        return null;
    }
    
    /**
     * Return the secret key ring which contains the key referred to by keyID.
     * 
     * @param keyID
     * @return the secret key ring
     * @throws PGPException
     */
    public PGPSecretKeyRing getSecretKeyRing(
        long    keyID) 
        throws PGPException
    {
        Long    id = new Long(keyID);
        
        if (secretRings.containsKey(id))
        {
            return (PGPSecretKeyRing)secretRings.get(id);
        }
        
        Iterator    it = this.getKeyRings();
        
        while (it.hasNext())
        {
            PGPSecretKeyRing    secretRing = (PGPSecretKeyRing)it.next();
            PGPSecretKey        secret = secretRing.getSecretKey(keyID);
            
            if (secret != null)
            {
                return secretRing;
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
            PGPSecretKeyRing    sr = (PGPSecretKeyRing)secretRings.get(it.next());
            
            sr.encode(out);
        }
    }
    
    /**
     * Return a new collection object containing the contents of the passed in collection and
     * the passed in secret key ring.
     * 
     * @param ringCollection the collection the ring to be added to.
     * @param secretKeyRing the key ring to be added.
     * @return a new collection merging the current one with the passed in ring.
     * @exception IllegalArgumentException if the keyID for the passed in ring is already present.
     */
    public static PGPSecretKeyRingCollection addSecretKeyRing(
        PGPSecretKeyRingCollection ringCollection,
        PGPSecretKeyRing           secretKeyRing)
    {
        Long        key = new Long(secretKeyRing.getPublicKey().getKeyID());
        
        if (ringCollection.secretRings.containsKey(key))
        {
            throw new IllegalArgumentException("Collection already contains a key with a keyID for the passed in ring.");
        }
        
        HashMap     newSecretRings = new HashMap(ringCollection.secretRings);
        ArrayList   newOrder = new ArrayList(ringCollection.order); 
        
        newSecretRings.put(key, secretKeyRing);
        newOrder.add(key);
        
        return new PGPSecretKeyRingCollection(newSecretRings, newOrder);
    }
    
    /**
     * Return a new collection object containing the contents of this collection with
     * the passed in secret key ring removed.
     * 
     * @param ringCollection the collection the ring to be removed from.
     * @param secretKeyRing the key ring to be removed.
     * @return a new collection merging the current one with the passed in ring.
     * @exception IllegalArgumentException if the keyID for the passed in ring is not present.
     */
    public static PGPSecretKeyRingCollection removeSecretKeyRing(
        PGPSecretKeyRingCollection ringCollection,
        PGPSecretKeyRing           secretKeyRing)
    {
        Long        key = new Long(secretKeyRing.getPublicKey().getKeyID());
        
        if (!ringCollection.secretRings.containsKey(key))
        {
            throw new IllegalArgumentException("Collection already contains a key with a keyID for the passed in ring.");
        }
        
        HashMap     newSecretRings = new HashMap(ringCollection.secretRings);
        ArrayList   newOrder = new ArrayList(ringCollection.order); 
        
        newSecretRings.remove(key);
        
        for (int i = 0; i < newOrder.size(); i++)
        {
            Long    r = (Long)newOrder.get(i);
            
            if (r.longValue() == key.longValue())
            {
                newOrder.remove(i);
                break;
            }
        }
        
        return new PGPSecretKeyRingCollection(newSecretRings, newOrder);
    }
}
