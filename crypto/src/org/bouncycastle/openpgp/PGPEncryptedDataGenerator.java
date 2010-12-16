package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.DigestOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.ContainedPacket;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PacketTags;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;

/**
 *  Generator for encrypted objects.
 */
public class PGPEncryptedDataGenerator
    implements SymmetricKeyAlgorithmTags, StreamGenerator
{
    /**
     * Specifier for SHA-1 S2K PBE generator.
     */
    public static final int S2K_SHA1 = HashAlgorithmTags.SHA1;

    /**
     * Specifier for SHA-224 S2K PBE generator.
     */
    public static final int S2K_SHA224 = HashAlgorithmTags.SHA224;

    /**
     * Specifier for SHA-256 S2K PBE generator.
     */
    public static final int S2K_SHA256 = HashAlgorithmTags.SHA256;

    /**
     * Specifier for SHA-384 S2K PBE generator.
     */
    public static final int S2K_SHA384 = HashAlgorithmTags.SHA384;

    /**
     * Specifier for SHA-512 S2K PBE generator.
     */
    public static final int S2K_SHA512 = HashAlgorithmTags.SHA512;

    private BCPGOutputStream     pOut;
    private CipherOutputStream   cOut;
    private Cipher               c;
    private boolean              withIntegrityPacket = false;
    private boolean              oldFormat = false;
    private DigestOutputStream   digestOut;
        
    private abstract class EncMethod
        extends ContainedPacket
    {
        protected byte[]     sessionInfo;
        protected int        encAlgorithm;
        protected Key        key;
        
        public abstract void addSessionInfo(
            byte[]    sessionInfo) 
            throws Exception;
    }
    
    private class PBEMethod
        extends EncMethod
    {
        S2K             s2k;

        PBEMethod(
            int        encAlgorithm,
            S2K        s2k,
            Key        key)
        {
            this.encAlgorithm = encAlgorithm;
            this.s2k = s2k;
            this.key = key;
        }

        public Key getKey()
        {
            return key;
        }

        public void addSessionInfo(
            byte[]    sessionInfo) 
            throws Exception
        {
            String        cName = PGPUtil.getSymmetricCipherName(encAlgorithm);
            Cipher        c = Cipher.getInstance(cName + "/CFB/NoPadding", defProvider);

            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[c.getBlockSize()]), rand);
        
            this.sessionInfo = c.doFinal(sessionInfo, 0, sessionInfo.length - 2);
        }

        public void encode(BCPGOutputStream pOut) 
            throws IOException
        {
            SymmetricKeyEncSessionPacket pk = new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, sessionInfo);

            pOut.writePacket(pk);
        }
    }

    private class PubMethod
        extends EncMethod
    {
        PGPPublicKey    pubKey;
        BigInteger[]    data;
        
        PubMethod(
            PGPPublicKey        pubKey)
        {
            this.pubKey = pubKey;
        }
    
        public void addSessionInfo(
            byte[]    sessionInfo) 
            throws Exception
        {
            Cipher            c;

            switch (pubKey.getAlgorithm())
            {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
                c = Cipher.getInstance("RSA/ECB/PKCS1Padding", defProvider);
                break;
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                c = Cipher.getInstance("ElGamal/ECB/PKCS1Padding", defProvider);
                break;
            case PGPPublicKey.DSA:
                throw new PGPException("Can't use DSA for encryption.");
            case PGPPublicKey.ECDSA:
                throw new PGPException("Can't use ECDSA for encryption.");
            default:
                throw new PGPException("unknown asymmetric algorithm: " + pubKey.getAlgorithm());
            }

            Key key = pubKey.getKey(defProvider);
            
            c.init(Cipher.ENCRYPT_MODE, key, rand);
        
            byte[]    encKey = c.doFinal(sessionInfo);
            
            switch (pubKey.getAlgorithm())
            {
            case PGPPublicKey.RSA_ENCRYPT:
            case PGPPublicKey.RSA_GENERAL:
                data = new BigInteger[1];
                
                data[0] = new BigInteger(1, encKey);
                break;
            case PGPPublicKey.ELGAMAL_ENCRYPT:
            case PGPPublicKey.ELGAMAL_GENERAL:
                byte[]        b1 = new byte[encKey.length / 2];
                byte[]        b2 = new byte[encKey.length / 2];
                
                System.arraycopy(encKey, 0, b1, 0, b1.length);
                System.arraycopy(encKey, b1.length, b2, 0, b2.length);
                
                data = new BigInteger[2];
                data[0] = new BigInteger(1, b1);
                data[1] = new BigInteger(1, b2);
                break;
            default:
                throw new PGPException("unknown asymmetric algorithm: " + encAlgorithm);
            }
        }
        
        public void encode(BCPGOutputStream pOut) 
            throws IOException
        {
            PublicKeyEncSessionPacket    pk = new PublicKeyEncSessionPacket(pubKey.getKeyID(), pubKey.getAlgorithm(), data);
            
            pOut.writePacket(pk);
        }
    }
    
    private List            methods = new ArrayList();
    private int             defAlgorithm;
    private SecureRandom    rand;
    private Provider        defProvider;
    
    /**
     * Base constructor.
     *
     * @param encAlgorithm the symmetric algorithm to use.
     * @param rand source of randomness
     * @param provider the provider to use for encryption algorithms.
     */
    public PGPEncryptedDataGenerator(
        int                 encAlgorithm,
        SecureRandom        rand,
        String              provider)
    {
        this(encAlgorithm, rand, Security.getProvider(provider));
    }

    public PGPEncryptedDataGenerator(
        int                 encAlgorithm,
        SecureRandom        rand,
        Provider            provider)
    {
        this.defAlgorithm = encAlgorithm;
        this.rand = rand;
        this.defProvider = provider;
    }

    /**
     * Creates a cipher stream which will have an integrity packet
     * associated with it.
     * 
     * @param encAlgorithm
     * @param withIntegrityPacket
     * @param rand
     * @param provider
     */
    public PGPEncryptedDataGenerator(
        int                 encAlgorithm,
        boolean             withIntegrityPacket,
        SecureRandom        rand,
        String              provider)
    {
        this(encAlgorithm, withIntegrityPacket, rand, Security.getProvider(provider));
    }

    public PGPEncryptedDataGenerator(
        int                 encAlgorithm,
        boolean             withIntegrityPacket,
        SecureRandom        rand,
        Provider            provider)
    {
        this.defAlgorithm = encAlgorithm;
        this.rand = rand;
        this.defProvider = provider;
        this.withIntegrityPacket = withIntegrityPacket;
    }

    /**
     * Base constructor.
     *
     * @param encAlgorithm the symmetric algorithm to use.
     * @param rand source of randomness
     * @param oldFormat PGP 2.6.x compatability required.
     * @param provider the provider to use for encryption algorithms.
     */
    public PGPEncryptedDataGenerator(
        int                 encAlgorithm,
        SecureRandom        rand,
        boolean             oldFormat,
        String              provider)
    {
        this.defAlgorithm = encAlgorithm;
        this.rand = rand;
        this.defProvider = Security.getProvider(provider);
        this.oldFormat = oldFormat;
    }

    public PGPEncryptedDataGenerator(
        int                 encAlgorithm,
        SecureRandom        rand,
        boolean             oldFormat,
        Provider            provider)
    {
        this.defAlgorithm = encAlgorithm;
        this.rand = rand;
        this.defProvider = provider;
        this.oldFormat = oldFormat;
    }

    /**
     * Add a PBE encryption method to the encrypted object using the default algorithm (S2K_SHA1).
     * 
     * @param passPhrase
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public void addMethod(
        char[]    passPhrase) 
        throws NoSuchProviderException, PGPException
    {
        addMethod(passPhrase, HashAlgorithmTags.SHA1);
    }

    /**
     * Add a PBE encryption method to the encrypted object.
     *
     * @param passPhrase passphrase to use to generate key.
     * @param s2kDigest digest algorithm to use for S2K calculation
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public void addMethod(
        char[]    passPhrase,
        int       s2kDigest)
        throws NoSuchProviderException, PGPException
    {
        if (defProvider == null)
        {
            throw new NoSuchProviderException("unable to find provider.");
        }

        byte[]        iv = new byte[8];

        rand.nextBytes(iv);

        S2K            s2k = new S2K(s2kDigest, iv, 0x60);

        methods.add(new PBEMethod(defAlgorithm, s2k, PGPUtil.makeKeyFromPassPhrase(defAlgorithm, s2k, passPhrase, defProvider)));
    }

    /**
     * Add a public key encrypted session key to the encrypted object.
     * 
     * @param key
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public void addMethod(
        PGPPublicKey    key) 
        throws NoSuchProviderException, PGPException
    {   
        if (!key.isEncryptionKey())
        {
            throw new IllegalArgumentException("passed in key not an encryption key!");
        }

        if (defProvider == null)
        {
            throw new NoSuchProviderException("unable to find provider.");
        }

        methods.add(new PubMethod(key));
    }
    
    private void addCheckSum(
        byte[]    sessionInfo)
    {
        int    check = 0;
        
        for (int i = 1; i != sessionInfo.length - 2; i++)
        {
            check += sessionInfo[i] & 0xff;
        }
        
        sessionInfo[sessionInfo.length - 2] = (byte)(check >> 8);
        sessionInfo[sessionInfo.length - 1] = (byte)(check);
    }

    private byte[] createSessionInfo(
        int algorithm,
        Key key)
    {
        byte[] keyBytes = key.getEncoded();
        byte[] sessionInfo = new byte[keyBytes.length + 3];
        sessionInfo[0] = (byte) algorithm;
        System.arraycopy(keyBytes, 0, sessionInfo, 1, keyBytes.length);
        addCheckSum(sessionInfo);
        return sessionInfo;
    }

    /**
     * If buffer is non null stream assumed to be partial, otherwise the
     * length will be used to output a fixed length packet.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     * 
     * @param out
     * @param length
     * @param buffer
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws IllegalStateException
     */
    private OutputStream open(
        OutputStream    out,
        long            length,
        byte[]          buffer)
        throws IOException, PGPException, IllegalStateException
    {
        if (cOut != null)
        {
            throw new IllegalStateException("generator already in open state");
        }

        if (methods.size() == 0)
        {
            throw new IllegalStateException("no encryption methods specified");
        }

        if (defProvider == null)
        {
            throw new IllegalStateException("provider resolves to null");
        }

        Key key = null;

        pOut = new BCPGOutputStream(out);

        if (methods.size() == 1)
        {    
            if (methods.get(0) instanceof PBEMethod)
            {
                PBEMethod m = (PBEMethod)methods.get(0);
                
                key = m.getKey();
            }
            else
            {
                key = PGPUtil.makeRandomKey(defAlgorithm, rand);
                byte[] sessionInfo = createSessionInfo(defAlgorithm, key);

                PubMethod m = (PubMethod)methods.get(0);

                try
                {
                    m.addSessionInfo(sessionInfo);
                }
                catch (Exception e)
                {
                    throw new PGPException("exception encrypting session key", e);
                }
            }
            
            pOut.writePacket((ContainedPacket)methods.get(0));
        }
        else // multiple methods
        {
            key = PGPUtil.makeRandomKey(defAlgorithm, rand);
            byte[] sessionInfo = createSessionInfo(defAlgorithm, key);

            for (int i = 0; i != methods.size(); i++)
            {
                EncMethod m = (EncMethod)methods.get(i);

                try
                {
                    m.addSessionInfo(sessionInfo);
                }
                catch (Exception e)
                {
                    throw new PGPException("exception encrypting session key", e);
                }

                pOut.writePacket(m);
            }
        }

        String cName = PGPUtil.getSymmetricCipherName(defAlgorithm);

        if (cName == null)
        {
            throw new PGPException("null cipher specified");
        }

        try
        {
            if (withIntegrityPacket)
            {
                c = Cipher.getInstance(cName + "/CFB/NoPadding", defProvider);
            }
            else
            {
                c = Cipher.getInstance(cName + "/OpenPGPCFB/NoPadding", defProvider);
            }

            byte[] iv = new byte[c.getBlockSize()];
            c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv), rand);
            
            if (buffer == null)
            {
                //
                // we have to add block size + 2 for the generated IV and + 1 + 22 if integrity protected
                //
                if (withIntegrityPacket)
                {
                    pOut = new BCPGOutputStream(out, PacketTags.SYM_ENC_INTEGRITY_PRO, length + c.getBlockSize() + 2 + 1 + 22);
                    pOut.write(1);        // version number
                }
                else
                {
                    pOut = new BCPGOutputStream(out, PacketTags.SYMMETRIC_KEY_ENC, length + c.getBlockSize() + 2, oldFormat);
                }
            }
            else
            {
                if (withIntegrityPacket)
                {
                    pOut = new BCPGOutputStream(out, PacketTags.SYM_ENC_INTEGRITY_PRO, buffer);
                    pOut.write(1);        // version number
                }
                else
                {
                    pOut = new BCPGOutputStream(out, PacketTags.SYMMETRIC_KEY_ENC, buffer);
                }
            }


            OutputStream genOut = cOut = new CipherOutputStream(pOut, c);

            if (withIntegrityPacket)
            {
                String digestName = PGPUtil.getDigestName(HashAlgorithmTags.SHA1);
                MessageDigest digest = MessageDigest.getInstance(digestName, defProvider);
                genOut = digestOut = new DigestOutputStream(cOut, digest);
            }

            byte[] inLineIv = new byte[c.getBlockSize() + 2];
            rand.nextBytes(inLineIv);
            inLineIv[inLineIv.length - 1] = inLineIv[inLineIv.length - 3];
            inLineIv[inLineIv.length - 2] = inLineIv[inLineIv.length - 4];

            genOut.write(inLineIv);

            return new WrappedGeneratorStream(genOut, this);
        }
        catch (Exception e)
        {
            throw new PGPException("Exception creating cipher", e);
        }
    }

    /**
     * Return an outputstream which will encrypt the data as it is written
     * to it.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     * 
     * @param out
     * @param length
     * @return OutputStream
     * @throws IOException
     * @throws PGPException
     */
    public OutputStream open(
        OutputStream    out,
        long            length)
        throws IOException, PGPException
    {
        return this.open(out, length, null);
    }
    
    /**
     * Return an outputstream which will encrypt the data as it is written
     * to it. The stream will be written out in chunks according to the size of the
     * passed in buffer.
     * <p>
     * The stream created can be closed off by either calling close()
     * on the stream or close() on the generator. Closing the returned
     * stream does not close off the OutputStream parameter out.
     * <p>
     * <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
     * bytes worth of the buffer will be used.
     * 
     * @param out
     * @param buffer the buffer to use.
     * @return OutputStream
     * @throws IOException
     * @throws PGPException
     */
    public OutputStream open(
        OutputStream    out,
        byte[]          buffer)
        throws IOException, PGPException
    {
        return this.open(out, 0, buffer);
    }
    
    /**
     * Close off the encrypted object - this is equivalent to calling close on the stream
     * returned by the open() method.
     * <p>
     * <b>Note</b>: This does not close the underlying output stream, only the stream on top of it created by the open() method.
     * @throws IOException
     */
    public void close()
        throws IOException
    {
        if (cOut != null)
        {    
            if (digestOut != null)
            {
                //
                // hand code a mod detection packet
                //
                BCPGOutputStream bOut = new BCPGOutputStream(digestOut, PacketTags.MOD_DETECTION_CODE, 20);

                bOut.flush();
                digestOut.flush();

                byte[] dig = digestOut.getMessageDigest().digest();

                cOut.write(dig);
            }

            cOut.flush();

            try
            {
                pOut.write(c.doFinal());
                pOut.finish();
            }
            catch (Exception e)
            {
                throw new IOException(e.toString());
            }

            cOut = null;
            pOut = null;
        }
    }
}
