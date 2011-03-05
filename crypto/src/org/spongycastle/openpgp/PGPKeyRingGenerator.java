package org.spongycastle.openpgp;

import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.spongycastle.bcpg.*;

/**
 * Generator for a PGP master and subkey ring. This class will generate
 * both the secret and public key rings
 */
public class PGPKeyRingGenerator
{    
    List                                keys = new ArrayList();
    
    private String                      id;
    private int                         encAlgorithm;
    private int                         certificationLevel;
    private char[]                      passPhrase;
    private boolean                     useSHA1;
    private PGPKeyPair                  masterKey;
    private PGPSignatureSubpacketVector hashedPcks;
    private PGPSignatureSubpacketVector unhashedPcks;
    private SecureRandom                rand;
    private Provider                    provider;
    
    /**
     * Create a new key ring generator using old style checksumming. It is recommended to use
     * SHA1 checksumming where possible.
     * 
     * @param certificationLevel the certification level for keys on this ring.
     * @param masterKey the master key pair.
     * @param id the id to be associated with the ring.
     * @param encAlgorithm the algorithm to be used to protect secret keys.
     * @param passPhrase the passPhrase to be used to protect secret keys.
     * @param hashedPcks packets to be included in the certification hash.
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
        this(certificationLevel, masterKey, id, encAlgorithm, passPhrase, false, hashedPcks, unhashedPcks, rand, provider);
    }

    /**
     * Create a new key ring generator.
     * 
     * @param certificationLevel the certification level for keys on this ring.
     * @param masterKey the master key pair.
     * @param id the id to be associated with the ring.
     * @param encAlgorithm the algorithm to be used to protect secret keys.
     * @param passPhrase the passPhrase to be used to protect secret keys.
     * @param useSHA1 checksum the secret keys with SHA1 rather than the older 16 bit checksum.
     * @param hashedPcks packets to be included in the certification hash.
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
        boolean                        useSHA1,
        PGPSignatureSubpacketVector    hashedPcks,
        PGPSignatureSubpacketVector    unhashedPcks,
        SecureRandom                   rand,
        String                         provider)
        throws PGPException, NoSuchProviderException
    {
        this(certificationLevel, masterKey, id, encAlgorithm, passPhrase, useSHA1, hashedPcks, unhashedPcks, rand, PGPUtil.getProvider(provider));
    }

    /**
     * Create a new key ring generator.
     *
     * @param certificationLevel the certification level for keys on this ring.
     * @param masterKey the master key pair.
     * @param id the id to be associated with the ring.
     * @param encAlgorithm the algorithm to be used to protect secret keys.
     * @param passPhrase the passPhrase to be used to protect secret keys.
     * @param useSHA1 checksum the secret keys with SHA1 rather than the older 16 bit checksum.
     * @param hashedPcks packets to be included in the certification hash.
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
        boolean                        useSHA1,
        PGPSignatureSubpacketVector    hashedPcks,
        PGPSignatureSubpacketVector    unhashedPcks,
        SecureRandom                   rand,
        Provider                       provider)
        throws PGPException, NoSuchProviderException
    {
        this.certificationLevel = certificationLevel;
        this.masterKey = masterKey;
        this.id = id;
        this.encAlgorithm = encAlgorithm;
        this.passPhrase = passPhrase;
        this.useSHA1 = useSHA1;
        this.hashedPcks = hashedPcks;
        this.unhashedPcks = unhashedPcks;
        this.rand = rand;
        this.provider = provider;

        keys.add(new PGPSecretKey(certificationLevel, masterKey, id, encAlgorithm, passPhrase, useSHA1, hashedPcks, unhashedPcks, rand, provider));
    }

    /**
     * Add a sub key to the key ring to be generated with default certification and inheriting
     * the hashed/unhashed packets of the master key.
     * 
     * @param keyPair
     * @throws PGPException
     */
    public void addSubKey(
        PGPKeyPair    keyPair) 
        throws PGPException
    {
        addSubKey(keyPair, hashedPcks, unhashedPcks);
    }
    
    /**
     * Add a subkey with specific hashed and unhashed packets associated with it and default
     * certification. 
     * 
     * @param keyPair public/private key pair.
     * @param hashedPcks hashed packet values to be included in certification.
     * @param unhashedPcks unhashed packets values to be included in certification.
     * @throws PGPException
     */
    public void addSubKey(
        PGPKeyPair                  keyPair,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks) 
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

            List                 subSigs = new ArrayList();
            
            subSigs.add(sGen.generateCertification(masterKey.getPublicKey(), keyPair.getPublicKey()));
            
            keys.add(new PGPSecretKey(keyPair.getPrivateKey(), new PGPPublicKey(keyPair.getPublicKey(), null, subSigs), encAlgorithm, passPhrase, useSHA1, rand, provider));
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
        Iterator it = keys.iterator();
        List     pubKeys = new ArrayList();
        
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
