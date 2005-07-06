package org.bouncycastle.openpgp;

import java.security.PrivateKey;

/**
 * general class to contain a private key for use with other openPGP
 * objects.
 */
public class PGPPrivateKey
{
    private long          keyID;
    private byte[]        fingerPrint;
    private PrivateKey    privateKey;
    
    PGPPrivateKey(
        PrivateKey        privateKey,
        long              keyID)
    {
        this.privateKey = privateKey;
        this.keyID = keyID;
    }

    /**
     * Return the keyID associated with the contained private key.
     * 
     * @return long
     */
    public long getKeyID()
    {
        return keyID;
    }
    
    /**
     * Return the contained private key.
     * 
     * @return PrivateKey
     */
    public PrivateKey getKey()
    {
        return privateKey;
    }
}
