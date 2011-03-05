package org.spongycastle.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Provider;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.spongycastle.bcpg.BCPGInputStream;
import org.spongycastle.bcpg.BCPGObject;
import org.spongycastle.bcpg.BCPGOutputStream;
import org.spongycastle.bcpg.ContainedPacket;
import org.spongycastle.bcpg.DSAPublicBCPGKey;
import org.spongycastle.bcpg.DSASecretBCPGKey;
import org.spongycastle.bcpg.ElGamalPublicBCPGKey;
import org.spongycastle.bcpg.ElGamalSecretBCPGKey;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.PublicKeyPacket;
import org.spongycastle.bcpg.RSAPublicBCPGKey;
import org.spongycastle.bcpg.RSASecretBCPGKey;
import org.spongycastle.bcpg.S2K;
import org.spongycastle.bcpg.SecretKeyPacket;
import org.spongycastle.bcpg.SecretSubkeyPacket;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.bcpg.UserAttributePacket;
import org.spongycastle.bcpg.UserIDPacket;
import org.spongycastle.jce.interfaces.ElGamalPrivateKey;
import org.spongycastle.jce.spec.ElGamalParameterSpec;
import org.spongycastle.jce.spec.ElGamalPrivateKeySpec;

/**
 * general class to handle a PGP secret key object.
 */
public class PGPSecretKey
{    
    final SecretKeyPacket secret;
    final PGPPublicKey    pub;

    PGPSecretKey(
        SecretKeyPacket secret,
        PGPPublicKey    pub)
    {
        this.secret = secret;
        this.pub = pub;
    }
    
    PGPSecretKey(
        PGPPrivateKey   privKey,
        PGPPublicKey    pubKey,
        int             encAlgorithm,
        char[]          passPhrase,
        boolean         useSHA1,
        SecureRandom    rand,
        Provider        provider)
        throws PGPException
    {
        this(privKey, pubKey, encAlgorithm, passPhrase, useSHA1, rand, false, provider);
    }
    
    PGPSecretKey(
        PGPPrivateKey   privKey,
        PGPPublicKey    pubKey,
        int             encAlgorithm,
        char[]          passPhrase,
        boolean         useSHA1,
        SecureRandom    rand,
        boolean         isMasterKey,
        Provider        provider) 
        throws PGPException
    {
        BCPGObject      secKey;

        this.pub = pubKey;
        
        switch (pubKey.getAlgorithm())
        {
        case PGPPublicKey.RSA_ENCRYPT:
        case PGPPublicKey.RSA_SIGN:
        case PGPPublicKey.RSA_GENERAL:
            RSAPrivateCrtKey    rsK = (RSAPrivateCrtKey)privKey.getKey();
            
            secKey = new RSASecretBCPGKey(rsK.getPrivateExponent(), rsK.getPrimeP(), rsK.getPrimeQ());
            break;
        case PGPPublicKey.DSA:
            DSAPrivateKey       dsK = (DSAPrivateKey)privKey.getKey();
            
            secKey = new DSASecretBCPGKey(dsK.getX());
            break;
        case PGPPublicKey.ELGAMAL_ENCRYPT:
        case PGPPublicKey.ELGAMAL_GENERAL:
            ElGamalPrivateKey   esK = (ElGamalPrivateKey)privKey.getKey();
            
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

            pOut.write(checksum(useSHA1, keyData, keyData.length));
            
            if (c != null)
            {
                byte[]       iv = new byte[8];
                
                rand.nextBytes(iv);
                
                S2K          s2k = new S2K(HashAlgorithmTags.SHA1, iv, 0x60);
                SecretKey    key = PGPUtil.makeKeyFromPassPhrase(encAlgorithm, s2k, passPhrase, provider);
    
                c.init(Cipher.ENCRYPT_MODE, key, rand);
            
                iv = c.getIV();
    
                byte[]    encData = c.doFinal(bOut.toByteArray());

                int s2kUsage;

                if (useSHA1)
                {
                    s2kUsage = SecretKeyPacket.USAGE_SHA1;
                }
                else
                {
                    s2kUsage = SecretKeyPacket.USAGE_CHECKSUM;
                }

                if (isMasterKey)
                {
                    this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                }
                else
                {
                    this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, s2kUsage, s2k, iv, encData);
                }
            }
            else
            {
                if (isMasterKey)
                {
                    this.secret = new SecretKeyPacket(pub.publicPk, encAlgorithm, null, null, bOut.toByteArray());
                }
                else
                {
                    this.secret = new SecretSubkeyPacket(pub.publicPk, encAlgorithm, null, null, bOut.toByteArray());
                }
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
        this(certificationLevel, keyPair, id, encAlgorithm, passPhrase, false, hashedPcks, unhashedPcks, rand, provider);
    }

    public PGPSecretKey(
        int                         certificationLevel,
        PGPKeyPair                  keyPair,
        String                      id,
        int                         encAlgorithm,
        char[]                      passPhrase,
        boolean                     useSHA1,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        SecureRandom                rand,
        String                      provider)
        throws PGPException, NoSuchProviderException
    {
        this(certificationLevel, keyPair, id, encAlgorithm, passPhrase, useSHA1, hashedPcks, unhashedPcks, rand, PGPUtil.getProvider(provider));
    }
    
    public PGPSecretKey(
        int                         certificationLevel,
        PGPKeyPair                  keyPair,
        String                      id,
        int                         encAlgorithm,
        char[]                      passPhrase,
        boolean                     useSHA1,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        SecureRandom                rand,
        Provider                    provider)
        throws PGPException
    {
        this(keyPair.getPrivateKey(), certifiedPublicKey(certificationLevel, keyPair, id, hashedPcks, unhashedPcks, provider), encAlgorithm, passPhrase, useSHA1, rand, true, provider);
    }

    private static PGPPublicKey certifiedPublicKey(
        int certificationLevel,
        PGPKeyPair keyPair,
        String id,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        Provider provider)
        throws PGPException
    {
        PGPSignatureGenerator    sGen;

        try
        {
            sGen = new PGPSignatureGenerator(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1, provider);
        }
        catch (Exception e)
        {
            throw new PGPException("creating signature generator: " + e, e);
        }

        //
        // generate the certification
        //
        sGen.initSign(certificationLevel, keyPair.getPrivateKey());

        sGen.setHashedSubpackets(hashedPcks);
        sGen.setUnhashedSubpackets(unhashedPcks);

        try
        {
            PGPSignature    certification = sGen.generateCertification(id, keyPair.getPublicKey());

            return PGPPublicKey.addCertification(keyPair.getPublicKey(), id, certification);
        }
        catch (Exception e)
        {
            throw new PGPException("exception doing certification: " + e, e);
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
        this(certificationLevel, new PGPKeyPair(algorithm,pubKey, privKey, time), id, encAlgorithm, passPhrase, hashedPcks, unhashedPcks, rand, provider);
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
        boolean                     useSHA1,
        PGPSignatureSubpacketVector hashedPcks,
        PGPSignatureSubpacketVector unhashedPcks,
        SecureRandom                rand,
        String                      provider)
        throws PGPException, NoSuchProviderException
    {
        this(certificationLevel, new PGPKeyPair(algorithm,pubKey, privKey, time), id, encAlgorithm, passPhrase, useSHA1, hashedPcks, unhashedPcks, rand, provider);
    }

    /**
     * Return true if this key has an algorithm type that makes it suitable to use for signing.
     * <p>
     * Note: with version 4 keys KeyFlags subpackets should also be considered when present for
     * determining the preferred use of the key.
     *
     * @return true if this key algorithm is suitable for use with signing.
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
        return pub.isMasterKey();
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
        char[]   passPhrase,
        Provider provider)
        throws PGPException
    {
        String          cName = PGPUtil.getSymmetricCipherName(secret.getEncAlgorithm());
        Cipher          c = null;
        
        if (cName != null)
        {
            try
            {
                c = Cipher.getInstance(cName + "/CFB/NoPadding", provider);
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
                        
                        boolean useSHA1 = secret.getS2KUsage() == SecretKeyPacket.USAGE_SHA1;
                        byte[] check = checksum(useSHA1, data, (useSHA1) ? data.length - 20 : data.length - 2);
                        
                        for (int i = 0; i != check.length; i++)
                        {
                            if (check[i] != data[data.length - check.length + i])
                            {
                                throw new PGPException("checksum mismatch at " + i + " of " + check.length);
                            }
                        }
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
        return extractPrivateKey(passPhrase, PGPUtil.getProvider(provider));
    }

    /**
     * Extract a PGPPrivate key from the SecretKey's encrypted contents.
     *
     * @param passPhrase
     * @param provider
     * @return PGPPrivateKey
     * @throws PGPException
     */
    public  PGPPrivateKey extractPrivateKey(
        char[]   passPhrase,
        Provider provider)
        throws PGPException
    {
        byte[] secKeyData = secret.getSecretKeyData();
        if (secKeyData == null || secKeyData.length < 1)
        {
            return null;
        }

        PublicKeyPacket pubPk = secret.getPublicKeyPacket();

        try
        {
            KeyFactory         fact;
            byte[]             data = extractKeyData(passPhrase, provider);
            BCPGInputStream    in = new BCPGInputStream(new ByteArrayInputStream(data));
        
            switch (pubPk.getAlgorithm())
            {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
            case PGPPublicKey.RSA_SIGN:
                RSAPublicBCPGKey        rsaPub = (RSAPublicBCPGKey)pubPk.getKey();
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
                DSAPublicBCPGKey    dsaPub = (DSAPublicBCPGKey)pubPk.getKey();
                DSASecretBCPGKey    dsaPriv = new DSASecretBCPGKey(in);
                DSAPrivateKeySpec   dsaPrivSpec =
                                            new DSAPrivateKeySpec(dsaPriv.getX(), dsaPub.getP(), dsaPub.getQ(), dsaPub.getG());

                fact = KeyFactory.getInstance("DSA", provider);

                return new PGPPrivateKey(fact.generatePrivate(dsaPrivSpec), this.getKeyID());
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                ElGamalPublicBCPGKey    elPub = (ElGamalPublicBCPGKey)pubPk.getKey();
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
    
    private static byte[] checksum(boolean useSHA1, byte[] bytes, int length) 
        throws PGPException
    {
        if (useSHA1)
        {
            try
            {
                MessageDigest dig = MessageDigest.getInstance("SHA1");

                dig.update(bytes, 0, length);

                return dig.digest();
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new PGPException("Can't find SHA-1", e);
            }
        }
        else
        {
            int       checksum = 0;
        
            for (int i = 0; i != length; i++)
            {
                checksum += bytes[i] & 0xff;
            }
        
            byte[] check = new byte[2];

            check[0] = (byte)(checksum >> 8);
            check[1] = (byte)checksum;

            return check;
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
        if (pub.trustPk != null)
        {
            out.writePacket(pub.trustPk);
        }
        
        if (pub.subSigs == null)        // is not a sub key
        {
            for (int i = 0; i != pub.keySigs.size(); i++)
            {
                ((PGPSignature)pub.keySigs.get(i)).encode(out);
            }
            
            for (int i = 0; i != pub.ids.size(); i++)
            {
                if (pub.ids.get(i) instanceof String)
                {
                    String    id = (String)pub.ids.get(i);
                    
                    out.writePacket(new UserIDPacket(id));
                }
                else
                {
                    PGPUserAttributeSubpacketVector    v = (PGPUserAttributeSubpacketVector)pub.ids.get(i);

                    out.writePacket(new UserAttributePacket(v.toSubpacketArray()));
                }
                
                if (pub.idTrusts.get(i) != null)
                {
                    out.writePacket((ContainedPacket)pub.idTrusts.get(i));
                }
                
                List         sigs = (ArrayList)pub.idSigs.get(i);
                
                for (int j = 0; j != sigs.size(); j++)
                {
                    ((PGPSignature)sigs.get(j)).encode(out);
                }
            }
        }
        else
        {        
            for (int j = 0; j != pub.subSigs.size(); j++)
            {
                ((PGPSignature)pub.subSigs.get(j)).encode(out);
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
     * @param provider name of the provider to use
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
        return copyWithNewPassword(key, oldPassPhrase, newPassPhrase, newEncAlgorithm, rand, PGPUtil.getProvider(provider));
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
        Provider        provider)
        throws PGPException
    {
        byte[]   rawKeyData = key.extractKeyData(oldPassPhrase, provider);
        int        s2kUsage = key.secret.getS2KUsage();
        byte[]           iv = null;
        S2K             s2k = null;
        byte[]      keyData;

        if (newEncAlgorithm == SymmetricKeyAlgorithmTags.NULL)
        {
            s2kUsage = SecretKeyPacket.USAGE_NONE;
            if (key.secret.getS2KUsage() == SecretKeyPacket.USAGE_SHA1)   // SHA-1 hash, need to rewrite checksum
            {
                keyData = new byte[rawKeyData.length - 18];

                System.arraycopy(rawKeyData, 0, keyData, 0, keyData.length - 2);

                byte[] check = checksum(false, keyData, keyData.length - 2);
                
                keyData[keyData.length - 2] = check[0];
                keyData[keyData.length - 1] = check[1];
            }
            else
            {
                keyData = rawKeyData;
            }
        }
        else
        {
            Cipher      c = null;
            String      cName = PGPUtil.getSymmetricCipherName(newEncAlgorithm);
            
            try
            {
                c = Cipher.getInstance(cName + "/CFB/NoPadding", provider);
            }
            catch (Exception e)
            {
                throw new PGPException("Exception creating cipher", e);
            }
            
            iv = new byte[8];
            
            rand.nextBytes(iv);
            
            s2k = new S2K(HashAlgorithmTags.SHA1, iv, 0x60);
            
            try
            {                
                SecretKey    sKey = PGPUtil.makeKeyFromPassPhrase(newEncAlgorithm, s2k, newPassPhrase, provider);

                c.init(Cipher.ENCRYPT_MODE, sKey, rand);
            
                iv = c.getIV();
                
                keyData = c.doFinal(rawKeyData);
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

        SecretKeyPacket             secret = null;
        if (key.secret instanceof SecretSubkeyPacket)
        {
            secret = new SecretSubkeyPacket(key.secret.getPublicKeyPacket(),
                newEncAlgorithm, s2kUsage, s2k, iv, keyData);
        }
        else
        {
            secret = new SecretKeyPacket(key.secret.getPublicKeyPacket(),
                newEncAlgorithm, s2kUsage, s2k, iv, keyData);
        }

        return new PGPSecretKey(secret, key.pub);
    }

    /**
     * Replace the passed the public key on the passed in secret key.
     *
     * @param secretKey secret key to change
     * @param publicKey new public key.
     * @return a new secret key.
     * @throws IllegalArgumentException if keyIDs do not match.
     */
    public static PGPSecretKey replacePublicKey(PGPSecretKey secretKey, PGPPublicKey publicKey)
    {
        if (publicKey.getKeyID() != secretKey.getKeyID())
        {
            throw new IllegalArgumentException("keyIDs do not match");
        }

        return new PGPSecretKey(secretKey.secret, publicKey);
    }
}
