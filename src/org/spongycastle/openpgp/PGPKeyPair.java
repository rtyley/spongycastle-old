package org.spongycastle.openpgp;

import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;


/**
 * General class to handle JCA key pairs and convert them into OpenPGP ones.
 * <p>
 * A word for the unwary, the KeyID for a OpenPGP public key is calculated from
 * a hash that includes the time of creation, if you pass a different date to the 
 * constructor below with the same public private key pair the KeyID will not be the
 * same as for previous generations of the key, so ideally you only want to do 
 * this once.
 */
public class PGPKeyPair
{
    PGPPublicKey        pub;
    PGPPrivateKey       priv;

    /**
     * @deprecated use version without provider.
     */
    public PGPKeyPair(
        int             algorithm,
        KeyPair         keyPair,
        Date            time,
        String          provider)
        throws PGPException, NoSuchProviderException
    {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate(), time, provider);
    }

    public PGPKeyPair(
        int             algorithm,
        KeyPair         keyPair,
        Date            time)
        throws PGPException
    {
        this(algorithm, keyPair.getPublic(), keyPair.getPrivate(), time);
    }

    /**
     * @deprecated use version without provider.
     */
    public PGPKeyPair(
        int             algorithm,
        PublicKey       pubKey,
        PrivateKey      privKey,
        Date            time,
        String          provider)
        throws PGPException, NoSuchProviderException
    {
        this(algorithm, pubKey, privKey, time);
    }

    public PGPKeyPair(
        int             algorithm,
        PublicKey       pubKey,
        PrivateKey      privKey,
        Date            time)
        throws PGPException
    {
        this.pub = new PGPPublicKey(algorithm, pubKey, time);
        this.priv = new PGPPrivateKey(privKey, pub.getKeyID());
    }

    /**
     * Create a key pair from a PGPPrivateKey and a PGPPublicKey.
     * 
     * @param pub the public key
     * @param priv the private key
     */
    public PGPKeyPair(
        PGPPublicKey    pub,
        PGPPrivateKey   priv)
    {
        this.pub = pub;
        this.priv = priv;
    }
    
    /**
     * Return the keyID associated with this key pair.
     * 
     * @return keyID
     */
    public long getKeyID()
    {
        return pub.getKeyID();
    }
    
    public PGPPublicKey getPublicKey()
    {
        return pub;
    }
    
    public PGPPrivateKey getPrivateKey()
    {
        return priv;
    }
}
