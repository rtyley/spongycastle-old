package org.bouncycastle.openpgp;

import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;

import org.bouncycastle.bcpg.*;

/**
 * Generator for a PGP master and subkey ring. This class will generate
 * both the secret and public key rings
 */
public class PGPKeyRingGenerator
{    
    ArrayList                           keys = new ArrayList();
    
    private String                      id;
    private int                         encAlgorithm;
    private int                         certificationLevel;
    private char[]                      passPhrase;
    private PGPKeyPair                  masterKey;
    private PGPSignatureSubpacketVector hashedPcks;
    private PGPSignatureSubpacketVector unhashedPcks;
    private SecureRandom                rand;
    private String                      provider;
    
    /**
     * Create a new key ring generator.
     * 
     * @param certificationLevel the certification level for keys on this ring.
     * @param masterKey the master key pair.
     * @param id the id to be associated with the ring.
     * @param encAlgorithm the algorithm to be used to protect secret keys.
     * @param passPhrase the passPhrase to be used to protect secret keys.
     * @param hashedPcks packets to be include in the certification hash.
     * @param unhashedPcks packets to be attached unhashed to the certification.
     * @param rand input secured random
     * @param provider the provider to use for encryption.
     * 
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public PGPKeyRingGenerator(
        int                            certificationLevel,
        PGPKeyPair                     masterKey,
        String                         id,
        int                            encAlgorithm,
        char[]                         passPhrase,
        PGPSignatureSubpacketVector    hashedPcks,
        PGPSignatureSubpacketVector    unhashedPcks,
        SecureRandom                   rand,
        String                         provider)
        throws PGPException, NoSuchProviderException
    {
        this.certificationLevel = certificationLevel;
        this.masterKey = masterKey;
        this.id = id;
        this.encAlgorithm = encAlgorithm;
        this.passPhrase = passPhrase;
        this.hashedPcks = hashedPcks;
        this.unhashedPcks = unhashedPcks;
        this.rand = rand;
        this.provider = provider;
        
        keys.add(new PGPSecretKey(certificationLevel, masterKey, id, encAlgorithm, passPhrase, hashedPcks, unhashedPcks, rand, provider));
    }
    
    /**
     * Add a sub key to the key ring to be generated with default certification.
     * 
     * @param keyPair
     * @throws PGPException
     */
    public void addSubKey(
        PGPKeyPair    keyPair) 
        throws PGPException
    {
        try
        {
            PGPSignatureGenerator    sGen = new PGPSignatureGenerator(masterKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1, provider);

            //
            // generate the certification
            //
            sGen.initSign(PGPSignature.SUBKEY_BINDING, masterKey.getPrivateKey());

            sGen.setHashedSubpackets(hashedPcks);
            sGen.setUnhashedSubpackets(unhashedPcks);

            ArrayList            subSigs = new ArrayList();
            
            subSigs.add(sGen.generateCertification(masterKey.getPublicKey(), keyPair.getPublicKey()));
            
            keys.add(new PGPSecretKey(keyPair, null, subSigs, encAlgorithm, passPhrase, rand, provider));
        }
        catch (PGPException e)
        {
            throw e;
        } 
        catch (Exception e)
        {
            throw new PGPException("exception adding subkey: ", e);
        }
    }
    
    /**
     * Return the secret key ring.
     * 
     * @return a secret key ring.
     */
    public PGPSecretKeyRing generateSecretKeyRing()
    {
        return new PGPSecretKeyRing(keys);
    }
    
    /**
     * Return the public key ring that corresponds to the secret key ring.
     * 
     * @return a public key ring.
     */
    public PGPPublicKeyRing generatePublicKeyRing()
    {
        Iterator    it = keys.iterator();
        ArrayList   pubKeys = new ArrayList();
        
        pubKeys.add(((PGPSecretKey)it.next()).getPublicKey());
        
        while (it.hasNext())
        {
            PGPPublicKey k = new PGPPublicKey(((PGPSecretKey)it.next()).getPublicKey());
            
            k.publicPk = new PublicSubkeyPacket(k.getAlgorithm(), k.getCreationTime(), k.publicPk.getKey());
            
            pubKeys.add(k);
        }
        
        return new PGPPublicKeyRing(pubKeys);
    }
}
