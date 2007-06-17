package org.bouncycastle.openpgp;

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

import org.bouncycastle.bcpg.BCPGInputStream;
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
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
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
    SecretKeyPacket secret;
    TrustPacket     trust;
    List            keySigs;
    List            ids;
    List            idTrusts;
    List            idSigs;
    PGPPublicKey    pub;
    List       subSigs = null;
    
    /**
     * copy constructor - master key.
     */
    private PGPSecretKey(
        SecretKeyPacket secret,
        TrustPacket     trust,
        List            keySigs,
        List            ids,
        List            idTrusts,
        List            idSigs,
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
        List            subSigs,
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
        List            keySigs,
        List            ids,
        List            idTrusts,
        List            idSigs)
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
        List            subSigs)
        throws IOException
    {
        this.secret = secret;
        this.trust = trust;
        this.subSigs = subSigs;
        this.pub = new PGPPublicKey(secret.getPublicKeyPacket(), trust, subSigs);
    }
    
    PGPSecretKey(
        PGPKeyPair      keyPair,
        TrustPacket     trust,
        List            subSigs,
        int             encAlgorithm,
        char[]          passPhrase,
        boolean         useSHA1,
        SecureRandom    rand,
        String          provider) 
        throws PGPException, NoSuchProviderException
    {
        this(keyPair, encAlgorithm, passPhrase, useSHA1, rand, provider);

        this.secret = new SecretSubkeyPacket(secret.getPublicKeyPacket(), secret.getEncAlgorithm(), secret.getS2KUsage(), secret.getS2K(), secret.getIV(), secret.getSecretKeyData());
        this.trust = trust;
        this.subSigs = subSigs;
        this.pub = new PGPPublicKey(keyPair.getPublicKey(), trust, subSigs);
    }
    
    PGPSecretKey(
        PGPKeyPair      keyPair,
        int             encAlgorithm,
        char[]          passPhrase,
        boolean         useSHA1,
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
    
                if (useSHA1)
                {
                    this.secret = new SecretKeyPacket(pubPk, encAlgorithm, SecretKeyPacket.USAGE_SHA1, s2k, iv, encData);
                }
                else
                {
                    this.secret = new SecretKeyPacket(pubPk, encAlgorithm, SecretKeyPacket.USAGE_CHECKSUM, s2k, iv, encData);
                }

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
        this(keyPair, encAlgorithm, passPhrase, useSHA1, rand, provider);

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
            
            List      sigList = new ArrayList();
            
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
        this(certificationLevel, new PGPKeyPair(algorithm,pubKey, privKey, time, provider), id, encAlgorithm, passPhrase, useSHA1, hashedPcks, unhashedPcks, rand, provider);
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
                
                List         sigs = (ArrayList)idSigs.get(i);
                
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
        byte[]   rawKeyData = key.extractKeyData(oldPassPhrase, provider);
        int        s2kUsage = key.secret.getS2KUsage();
        byte[]           iv = null;
        S2K             s2k = null;
        byte[]      keyData = null;

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
            catch (NoSuchProviderException e)
            {
                throw e;
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
