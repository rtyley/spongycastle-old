package org.bouncycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.BCPGObject;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.DSASecretBCPGKey;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.ElGamalSecretBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SecretKeyPacket;
import org.bouncycastle.bcpg.SecretSubkeyPacket;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.bcpg.UserAttributePacket;
import org.bouncycastle.bcpg.UserIDPacket;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;

/**
 * general class to handle a PGP secret key object.
 */
public class PGPSecretKey
{
    private long    keyID;
    private byte[]  fingerPrint;
    
    SecretKeyPacket secret;
    TrustPacket     trust;
    ArrayList       keySigs;
    ArrayList       ids;
    ArrayList       idTrusts;
    ArrayList       idSigs;
    PGPPublicKey    pub;
    ArrayList       subSigs = null;
    
    /**
     * copy constructor - master key.
     */
    private PGPSecretKey(
        SecretKeyPacket secret,
        TrustPacket     trust,
        ArrayList       keySigs,
        ArrayList       ids,
        ArrayList       idTrusts,
        ArrayList       idSigs,
        PGPPublicKey    pub)
    {
        this.secret = secret;
        this.trust = trust;
        this.keySigs = keySigs;
        this.ids = ids;
        this.idTrusts = idTrusts;
        this.idSigs = idSigs;
        this.pub = pub;
    }

    /**
     * copy constructor - subkey.
     */
    private PGPSecretKey(
        SecretKeyPacket secret,
        TrustPacket     trust,
        ArrayList       subSigs,
        PGPPublicKey    pub)
    {
        this.secret = secret;
        this.trust = trust;
        this.subSigs = subSigs;
        this.pub = pub;
    }

    PGPSecretKey(
        SecretKeyPacket secret,
        TrustPacket     trust,
        MessageDigest   sha,
        ArrayList       keySigs,
        ArrayList       ids,
        ArrayList       idTrusts,
        ArrayList       idSigs)
        throws IOException
    {
        this.secret = secret;
        this.trust = trust;
        this.keySigs = keySigs;
        this.ids = ids;
        this.idTrusts = idTrusts;
        this.idSigs = idSigs;
        this.pub = new PGPPublicKey(secret.getPublicKeyPacket(), trust, keySigs, ids, idTrusts, idSigs);
    }
    
    PGPSecretKey(
        SecretKeyPacket secret,
        TrustPacket     trust,
        MessageDigest   sha,
        ArrayList       subSigs)
        throws IOException
    {
        this.secret = secret;
        this.trust = trust;
        this.subSigs = subSigs;
        this.pub = new PGPPublicKey(secret.getPublicKeyPacket(), trust, subSigs);
    }
    
    /**
     * Create a sub key.
     * 
     * @param keyPair
     * @param trust
     * @param subSigs
     * @param encAlgorithm
     * @param passPhrase
     * @param rand
     * @param provider
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    PGPSecretKey(
        PGPKeyPair      keyPair,
        TrustPacket     trust,
        ArrayList       subSigs,
        int             encAlgorithm,
        char[]          passPhrase,
        SecureRandom    rand,
        String          provider) 
        throws PGPException, NoSuchProviderException
    {
        this(keyPair, encAlgorithm, passPhrase, rand, provider);

        this.secret = new SecretSubkeyPacket(secret.getPublicKeyPacket(), secret.getEncAlgorithm(), secret.getS2K(), secret.getIV(), secret.getSecretKeyData());
        this.trust = trust;
        this.subSigs = subSigs;
        this.pub = new PGPPublicKey(keyPair.getPublicKey(), trust, subSigs);
    }
    
    PGPSecretKey(
        PGPKeyPair      keyPair,
        int             encAlgorithm,
        char[]          passPhrase,
        SecureRandom    rand,
        String          provider) 
        throws PGPException, NoSuchProviderException
    {
        PublicKeyPacket pubPk;
        BCPGObject      secKey;
        
        pubPk = keyPair.getPublicKey().publicPk;
        
        switch (keyPair.getPublicKey().getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_SIGN:
        case PGPPublicKey.RSA_GENERAL:
            RSAPrivateCrtKey    rsK = (RSAPrivateCrtKey)keyPair.getPrivateKey().getKey();
            
            secKey = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
            break;
        case PGPPublicKey.DSA:
            DSAPrivateKey       dsK = (DSAPrivateKey)keyPair.getPrivateKey().getKey();
            
            secKey = new DSASecretBCPGKey(dsK.getX());
            break;
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            ElGamalPrivateKey   esK = (ElGamalPrivateKey)keyPair.getPrivateKey().getKey();
            
            secKey = new ElGamalSecretBCPGKey(esK.getX());
            break;
        default:
            throw new PGPException("unknown key class");
        }

        String    cName = PGPUtil.getSymmetricCipherName(encAlgorithm);
        Cipher    c = null;
        
        if (cName != null)
        {
            try
            {
                c = Cipher.getInstance(cName + "/CFB/NoPadding", provider);
            }
            catch (NoSuchProviderException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PGPException("Exception creating cipher", e);
            }
        }
        
        try
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            BCPGOutputStream        pOut = new BCPGOutputStream(bOut);
            
            pOut.writeObject(secKey);
            
            byte[]    keyData = bOut.toByteArray();
            int       checkSum = 0;
            
            for (int i = 0; i != keyData.length; i++)
            {
                checkSum += keyData[i] & 0xff;
            }
            
            pOut.write(checkSum >> 8);
            pOut.write(checkSum);
            
            if (c != null)
            {
                byte[]       iv = new byte[8];
                
                rand.nextBytes(iv);
                
                S2K          s2k = new S2K(HashAlgorithmTags.SHA1, iv, 0x60);
                SecretKey    key = PGPUtil.makeKeyFromPassPhrase(encAlgorithm, s2k, passPhrase, provider);
    
                c.init(Cipher.ENCRYPT_MODE, key, rand);
            
                iv = c.getIV();
    
                byte[]    encData = c.doFinal(bOut.toByteArray());
    
                this.secret = new SecretKeyPacket(pubPk, encAlgorithm, s2k, iv, encData);
                this.trust = null;
            }
            else
            {
                this.secret = new SecretKeyPacket(pubPk, encAlgorithm, null, null, bOut.toByteArray());
                this.trust = null;
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception encrypting key", e);
        }
        
        this.keySigs = new ArrayList();
    }
    
    public PGPSecretKey(
        int                         certificationLevel,
        PGPKeyPair                  keyPair,
        String                      id,
        int                         encAlgorithm,
        char[]                      passPhrase,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        SecureRandom                rand,
        String                      provider)
        throws PGPException, NoSuchProviderException
    {
        this(keyPair, encAlgorithm, passPhrase, rand, provider);

        try
        {
            this.trust = null;
            
            this.ids = new ArrayList();
            ids.add(id);
            
            this.idTrusts = new ArrayList();
            idTrusts.add(null);
            
            this.idSigs = new ArrayList();
            
            PGPSignatureGenerator    sGen = new PGPSignatureGenerator(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1, provider);
            
            //
            // generate the certification
            //
            sGen.initSign(certificationLevel, keyPair.getPrivateKey());
            
            sGen.setHashedSubpackets(hashedPcks);
            sGen.setUnhashedSubpackets(unhashedPcks);
            
            PGPSignature    certification = sGen.generateCertification(id, keyPair.getPublicKey());
                
            this.pub = PGPPublicKey.addCertification(keyPair.getPublicKey(), id, certification);
            
            ArrayList sigList = new ArrayList();
            
            sigList.add(certification);
            
            idSigs.add(sigList);
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception encrypting key", e);
        }
    }
    
    public PGPSecretKey(
        int                         certificationLevel,
        int                         algorithm,
        PublicKey                   pubKey,
        PrivateKey                  privKey,
        Date                        time,
        String                      id,
        int                         encAlgorithm,
        char[]                      passPhrase,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        SecureRandom                rand,
        String                      provider)
        throws PGPException, NoSuchProviderException
    {
        this(certificationLevel, new PGPKeyPair(algorithm,pubKey, privKey, time, provider), id, encAlgorithm, passPhrase, hashedPcks, unhashedPcks, rand, provider);
    }

    /**
     * return true if this key is marked as suitable for signature generation.
     */
    public boolean isSigningKey()
    {
        int algorithm = pub.getAlgorithm();

        return ((algorithm == PGPPublicKey.RSA_GENERAL) || (algorithm == PGPPublicKey.RSA_SIGN)
                    || (algorithm == PGPPublicKey.DSA) || (algorithm == PGPPublicKey.ECDSA) || (algorithm == PGPPublicKey.ELGAMAL_GENERAL));
    }
    
    /**
     * Return true if this is a master key.
     * @return true if a master key.
     */
    public boolean isMasterKey()
    {
        return (subSigs == null);
    }
    
    /**
     * return the algorithm the key is encrypted with.
     *
     * @return the algorithm used to encrypt the secret key.
     */
    public int getKeyEncryptionAlgorithm()
    {
        return secret.getEncAlgorithm();
    }

    /**
     * Return the keyID of the public key associated with this key.
     * 
     * @return the keyID associated with this key.
     */
    public long getKeyID()
    {
        return pub.getKeyID();
    }
    
    /**
     * Return the public key associated with this key.
     * 
     * @return the public key for this key.
     */
    public PGPPublicKey getPublicKey()
    {
        return pub;
    }
    
    /**
     * Return any userIDs associated with the key.
     * 
     * @return an iterator of Strings.
     */
    public Iterator getUserIDs()
    {
        return pub.getUserIDs();
    }
    
    /**
     * Return any user attribute vectors associated with the key.
     * 
     * @return an iterator of Strings.
     */
    public Iterator getUserAttributes()
    {
        return pub.getUserAttributes();
    }
    
    private byte[] extractKeyData(
        char[] passPhrase,
        String provider)
        throws PGPException, NoSuchProviderException
    {
        PublicKeyPacket pub = secret.getPublicKeyPacket();
        BCPGKey         sKey = null;
        String          cName = PGPUtil.getSymmetricCipherName(secret.getEncAlgorithm());
        Cipher          c = null;
        
        if (cName != null)
        {
            try
            {
                c = Cipher.getInstance(cName + "/CFB/NoPadding", provider);
            }
            catch (NoSuchProviderException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PGPException("Exception creating cipher", e);
            }
        }
    
        byte[]    encData = secret.getSecretKeyData();
        byte[]    data = null;
    
        try
        {
            if (c != null)
            {
                try
                {
                    if (secret.getPublicKeyPacket().getVersion() == 4)
                    {
                        IvParameterSpec ivSpec = new IvParameterSpec(secret.getIV());
        
                        SecretKey    key = PGPUtil.makeKeyFromPassPhrase(secret.getEncAlgorithm(), secret.getS2K(), passPhrase, provider);
        
                        c.init(Cipher.DECRYPT_MODE, key, ivSpec);
                    
                        data = c.doFinal(encData, 0, encData.length);
                    }
                    else // version 2 or 3, RSA only.
                    {
                        SecretKey    key = PGPUtil.makeKeyFromPassPhrase(secret.getEncAlgorithm(), secret.getS2K(), passPhrase, provider);
    
                        data = new byte[encData.length];
                
                        byte[]    iv = new byte[secret.getIV().length];
                
                        System.arraycopy(secret.getIV(), 0, iv, 0, iv.length);
                
                        //
                        // read in the four numbers
                        //
                        int    pos = 0;
                        
                        for (int i = 0; i != 4; i++)
                        {
                            c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                    
                            int encLen = (((encData[pos] << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

                            data[pos] = encData[pos];
                            data[pos + 1] = encData[pos + 1];

                            c.doFinal(encData, pos + 2, encLen, data, pos + 2);
                            pos += 2 + encLen;
                
                            if (i != 3)
                            {
                                System.arraycopy(encData, pos - iv.length, iv, 0, iv.length);
                            }
                        }

                        //
                        // verify checksum
                        //
                        
                        int cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
                        int calcCs = 0;
                        for (int j=0; j < data.length-2; j++) 
                        {
                            calcCs += data[j] & 0xff;
                        }
            
                        calcCs &= 0xffff;
                        if (calcCs != cs) 
                        {
                            throw new PGPException("checksum mismatch: passphrase wrong, expected "
                                                + Integer.toHexString(cs)
                                                + " found " + Integer.toHexString(calcCs));
                        }
                    }
                }
                catch (PGPException e)
                {
                    throw e;
                }
                catch (Exception e)
                {
                    throw new PGPException("Exception decrypting key", e);
                }
            }
            else
            {
                data = encData;
            }

            return data;
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception constructing key", e);
        }
    }

    /**
     * Extract a PGPPrivate key from the SecretKey's encrypted contents.
     * 
     * @param passPhrase
     * @param provider
     * @return PGPPrivateKey
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    public  PGPPrivateKey extractPrivateKey(
        char[]                passPhrase,
        String                provider)
        throws PGPException, NoSuchProviderException
    {
        PublicKeyPacket            pub = secret.getPublicKeyPacket();
        BCPGKey                    sKey = null;
    
        if (secret.getSecretKeyData() == null)
        {
            return null;
        }
        
        try
        {
            KeyFactory         fact;
            byte[]             data = extractKeyData(passPhrase, provider);
            BCPGInputStream    in = new BCPGInputStream(new ByteArrayInputStream(data));
        
            switch (pub.getAlgorithm())
            {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
            case PGPPublicKey.RSA_SIGN:
                RSAPublicBCPGKey        rsaPub = (RSAPublicBCPGKey)pub.getKey();
                RSASecretBCPGKey        rsaPriv = new RSASecretBCPGKey(in);
                RSAPrivateCrtKeySpec    rsaPrivSpec = new RSAPrivateCrtKeySpec(
                                                    rsaPriv.getModulus(), 
                                                    rsaPub.getPublicExponent(),
                                                    rsaPriv.getPrivateExponent(),
                                                    rsaPriv.getPrimeP(),
                                                    rsaPriv.getPrimeQ(),
                                                    rsaPriv.getPrimeExponentP(),
                                                    rsaPriv.getPrimeExponentQ(),
                                                    rsaPriv.getCrtCoefficient());
                                    
                fact = KeyFactory.getInstance("RSA", provider);

                return new PGPPrivateKey(fact.generatePrivate(rsaPrivSpec), this.getKeyID());    
            case PGPPublicKey.DSA:
                DSAPublicBCPGKey    dsaPub = (DSAPublicBCPGKey)pub.getKey();
                DSASecretBCPGKey    dsaPriv = new DSASecretBCPGKey(in);
                DSAPrivateKeySpec   dsaPrivSpec =
                                            new DSAPrivateKeySpec(dsaPriv.getX(), dsaPub.getP(), dsaPub.getQ(), dsaPub.getG());

                fact = KeyFactory.getInstance("DSA", provider);

                return new PGPPrivateKey(fact.generatePrivate(dsaPrivSpec), this.getKeyID());
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                ElGamalPublicBCPGKey    elPub = (ElGamalPublicBCPGKey)pub.getKey();
                ElGamalSecretBCPGKey    elPriv = new ElGamalSecretBCPGKey(in);
                ElGamalPrivateKeySpec   elSpec = new ElGamalPrivateKeySpec(elPriv.getX(), new ElGamalParameterSpec(elPub.getP(), elPub.getG()));
            
                fact = KeyFactory.getInstance("ElGamal", provider);
            
                return new PGPPrivateKey(fact.generatePrivate(elSpec), this.getKeyID());
            default:
                throw new PGPException("unknown public key algorithm encountered");
            }
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception constructing key", e);
        }
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

        out.writePacket(secret);
        if (trust != null)
        {
            out.writePacket(trust);
        }
        
        if (subSigs == null)        // is not a sub key
        {
            for (int i = 0; i != keySigs.size(); i++)
            {
                ((PGPSignature)keySigs.get(i)).encode(out);
            }
            
            for (int i = 0; i != ids.size(); i++)
            {
                if (ids.get(i) instanceof String)
                {
                    String    id = (String)ids.get(i);
                    
                    out.writePacket(new UserIDPacket(id));
                }
                else
                {
                    PGPUserAttributeSubpacketVector    v = (PGPUserAttributeSubpacketVector)ids.get(i);

                    out.writePacket(new UserAttributePacket(v.toSubpacketArray()));
                }
                
                if (idTrusts.get(i) != null)
                {
                    out.writePacket((ContainedPacket)idTrusts.get(i));
                }
                
                ArrayList    sigs = (ArrayList)idSigs.get(i);
                
                for (int j = 0; j != sigs.size(); j++)
                {
                    ((PGPSignature)sigs.get(j)).encode(out);
                }
            }
        }
        else
        {        
            for (int j = 0; j != subSigs.size(); j++)
            {
                ((PGPSignature)subSigs.get(j)).encode(out);
            }
        }
    }

    /**
     * Return a copy of the passed in secret key, encrypted using a new
     * password and the passed in algorithm.
     *
     * @param key the PGPSecretKey to be copied.
     * @param oldPassPhrase the current password for key.
     * @param newPassPhrase the new password for the key.
     * @param newEncAlgorithm the algorithm to be used for the encryption.
     * @param rand source of randomness.
     * @param provider the provider to use
     */
    public static PGPSecretKey copyWithNewPassword(
        PGPSecretKey    key,
        char[]          oldPassPhrase,
        char[]          newPassPhrase,
        int             newEncAlgorithm,
        SecureRandom    rand,
        String          provider)
        throws PGPException, NoSuchProviderException
    {
        byte[]      keyData = key.extractKeyData(oldPassPhrase, provider);
        Cipher      c = null;
        String      cName = PGPUtil.getSymmetricCipherName(newEncAlgorithm);
        
        try
        {
            c = Cipher.getInstance(cName + "/CFB/NoPadding", provider);
        }
        catch (NoSuchProviderException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
        
        byte[]                      iv = new byte[8];
        
        rand.nextBytes(iv);
        
        S2K                         s2k = new S2K(HashAlgorithmTags.SHA1, iv, 0x60);
        SecretKeyPacket             secret = null;
        
        try
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            BCPGOutputStream        pOut = new BCPGOutputStream(bOut);
            
            SecretKey    sKey = PGPUtil.makeKeyFromPassPhrase(newEncAlgorithm, s2k, newPassPhrase, provider);

            c.init(Cipher.ENCRYPT_MODE, sKey, rand);
        
            iv = c.getIV();
            
            byte[]    encData = c.doFinal(keyData);
            
            secret = new SecretKeyPacket(key.secret.getPublicKeyPacket(), newEncAlgorithm, s2k, iv, encData);
        }
        catch (PGPException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new PGPException("Exception encrypting key", e);
        }

        if (key.subSigs == null)
        {
            return new PGPSecretKey(
                          secret, key.trust, key.keySigs, key.ids,
                                          key.idTrusts, key.idSigs, key.pub);
        }
        else
        {
            return new PGPSecretKey(secret, key.trust, key.subSigs, key.pub);
        }
    }
}
