package org.spongycastle.openpgp;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.bcpg.ArmoredInputStream;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.bcpg.MPInteger;
import org.spongycastle.bcpg.PublicKeyAlgorithmTags;
import org.spongycastle.bcpg.S2K;
import org.spongycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.util.encoders.Base64;

/**
 * Basic utility class
 */
public class PGPUtil
    implements HashAlgorithmTags
{
	private static String defProvider = BouncyCastleProvider.PROVIDER_NAME;

    /**
     * Return the provider that will be used by factory classes in situations
     * where a provider must be determined on the fly.
     * 
     * @return String
     */
    public static String getDefaultProvider()
    {
        return defProvider;
    }
    
    /**
     * Set the provider to be used by the package when it is necessary to 
     * find one on the fly.
     * 
     * @param provider
     */
    public static void setDefaultProvider(
        String    provider)
    {
        defProvider = provider;
    }
    
    static MPInteger[] dsaSigToMpi(
        byte[] encoding) 
        throws PGPException
    {
        ASN1InputStream aIn = new ASN1InputStream(encoding);

        DERInteger i1;
        DERInteger i2;

        try
        {
            ASN1Sequence s = (ASN1Sequence)aIn.readObject();

            i1 = (DERInteger)s.getObjectAt(0);
            i2 = (DERInteger)s.getObjectAt(1);
        }
        catch (IOException e)
        {
            throw new PGPException("exception encoding signature", e);
        }

        MPInteger[] values = new MPInteger[2];
        
        values[0] = new MPInteger(i1.getValue());
        values[1] = new MPInteger(i2.getValue());
        
        return values;
    }
    
    static String getDigestName(
        int        hashAlgorithm)
        throws PGPException
    {
        switch (hashAlgorithm)
        {
        case HashAlgorithmTags.SHA1:
            return "SHA1";
        case HashAlgorithmTags.MD2:
            return "MD2";
        case HashAlgorithmTags.MD5:
            return "MD5";
        case HashAlgorithmTags.RIPEMD160:
            return "RIPEMD160";
        case HashAlgorithmTags.SHA256:
            return "SHA256";
        case HashAlgorithmTags.SHA384:
            return "SHA384";
        case HashAlgorithmTags.SHA512:
            return "SHA512";
        case HashAlgorithmTags.SHA224:
            return "SHA224";
        default:
            throw new PGPException("unknown hash algorithm tag in getDigestName: " + hashAlgorithm);
        }
    }
    
    static String getSignatureName(
        int        keyAlgorithm,
        int        hashAlgorithm)
        throws PGPException
    {
        String     encAlg;
                
        switch (keyAlgorithm)
        {
        case PublicKeyAlgorithmTags.RSA_GENERAL:
        case PublicKeyAlgorithmTags.RSA_SIGN:
            encAlg = "RSA";
            break;
        case PublicKeyAlgorithmTags.DSA:
            encAlg = "DSA";
            break;
        case PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT: // in some malformed cases.
        case PublicKeyAlgorithmTags.ELGAMAL_GENERAL:
            encAlg = "ElGamal";
            break;
        default:
            throw new PGPException("unknown algorithm tag in signature:" + keyAlgorithm);
        }

        return getDigestName(hashAlgorithm) + "with" + encAlg;
    }
    
    static String getSymmetricCipherName(
        int    algorithm) 
        throws PGPException
    {
        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.NULL:
            return null;
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            return "DESEDE";
        case SymmetricKeyAlgorithmTags.IDEA:
            return "IDEA";
        case SymmetricKeyAlgorithmTags.CAST5:
            return "CAST5";
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            return "Blowfish";
        case SymmetricKeyAlgorithmTags.SAFER:
            return "SAFER";
        case SymmetricKeyAlgorithmTags.DES:
            return "DES";
        case SymmetricKeyAlgorithmTags.AES_128:
            return "AES";
        case SymmetricKeyAlgorithmTags.AES_192:
            return "AES";
        case SymmetricKeyAlgorithmTags.AES_256:
            return "AES";
        case SymmetricKeyAlgorithmTags.TWOFISH:
            return "Twofish";
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }
    }
    
    public static SecretKey makeRandomKey(
        int             algorithm,
        SecureRandom    random) 
        throws PGPException
    {
        String    algName = null;
        int        keySize = 0;
        
        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            keySize = 192;
            algName = "DES_EDE";
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
            keySize = 128;
            algName = "IDEA";
            break;
        case SymmetricKeyAlgorithmTags.CAST5:
            keySize = 128;
            algName = "CAST5";
            break;
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            keySize = 128;
            algName = "Blowfish";
            break;
        case SymmetricKeyAlgorithmTags.SAFER:
            keySize = 128;
            algName = "SAFER";
            break;
        case SymmetricKeyAlgorithmTags.DES:
            keySize = 64;
            algName = "DES";
            break;
        case SymmetricKeyAlgorithmTags.AES_128:
            keySize = 128;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.AES_192:
            keySize = 192;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.AES_256:
            keySize = 256;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.TWOFISH:
            keySize = 256;
            algName = "Twofish";
            break;
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }
        
        byte[]    keyBytes = new byte[(keySize + 7) / 8];
        
        random.nextBytes(keyBytes);
        
        return new SecretKeySpec(keyBytes, algName);
    }
    
    public static SecretKey makeKeyFromPassPhrase(
        int       algorithm,
        char[]    passPhrase,
        String    provider) 
        throws NoSuchProviderException, PGPException
    {
        return makeKeyFromPassPhrase(algorithm, null, passPhrase, provider);
    }
    
    public static SecretKey makeKeyFromPassPhrase(
        int     algorithm,
        S2K     s2k,
        char[]  passPhrase,
        String  provider) 
        throws PGPException, NoSuchProviderException
    {
        Provider prov = getProvider(provider);

        return makeKeyFromPassPhrase(algorithm, s2k, passPhrase, prov);
    }

    public static SecretKey makeKeyFromPassPhrase(
        int     algorithm,
        S2K     s2k,
        char[]  passPhrase,
        Provider provider)
        throws PGPException, NoSuchProviderException
    {
        String    algName = null;
        int        keySize = 0;
        
        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            keySize = 192;
            algName = "DES_EDE";
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
            keySize = 128;
            algName = "IDEA";
            break;
        case SymmetricKeyAlgorithmTags.CAST5:
            keySize = 128;
            algName = "CAST5";
            break;
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            keySize = 128;
            algName = "Blowfish";
            break;
        case SymmetricKeyAlgorithmTags.SAFER:
            keySize = 128;
            algName = "SAFER";
            break;
        case SymmetricKeyAlgorithmTags.DES:
            keySize = 64;
            algName = "DES";
            break;
        case SymmetricKeyAlgorithmTags.AES_128:
            keySize = 128;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.AES_192:
            keySize = 192;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.AES_256:
            keySize = 256;
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.TWOFISH:
            keySize = 256;
            algName = "Twofish";
            break;
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }
        
        byte[]           pBytes = new byte[passPhrase.length];
        MessageDigest    digest;
                    
        for (int i = 0; i != passPhrase.length; i++)
        {
            pBytes[i] = (byte)passPhrase[i];
        }
        
        byte[]    keyBytes = new byte[(keySize + 7) / 8];
        
        int    generatedBytes = 0;
        int    loopCount = 0;
        
        while (generatedBytes < keyBytes.length)
        {
            if (s2k != null)
            {     
                String digestName = getDigestName(s2k.getHashAlgorithm());

                try
                {
                    digest = getDigestInstance(digestName, provider);
                }
                catch (NoSuchAlgorithmException e)
                {
                    throw new PGPException("can't find S2K digest", e);
                }

                for (int i = 0; i != loopCount; i++)
                {
                    digest.update((byte)0);
                }
                
                byte[]    iv = s2k.getIV();
                            
                switch (s2k.getType())
                {
                case S2K.SIMPLE:
                    digest.update(pBytes);
                    break;
                case S2K.SALTED:
                    digest.update(iv);
                    digest.update(pBytes);
                    break;
                case S2K.SALTED_AND_ITERATED:
                    long    count = s2k.getIterationCount();
                    digest.update(iv);
                    digest.update(pBytes);
        
                    count -= iv.length + pBytes.length;
                                
                    while (count > 0)
                    {
                        if (count < iv.length)
                        {
                            digest.update(iv, 0, (int)count);
                            break;
                        }
                        else
                        {
                            digest.update(iv);
                            count -= iv.length;
                        }
        
                        if (count < pBytes.length)
                        {
                            digest.update(pBytes, 0, (int)count);
                            count = 0;
                        }
                        else
                        {
                            digest.update(pBytes);
                            count -= pBytes.length;
                        }
                    }
                    break;
                default:
                    throw new PGPException("unknown S2K type: " + s2k.getType());
                }
            }
            else
            {
                try
                {
                    digest = getDigestInstance("MD5", provider);
                }
                catch (NoSuchAlgorithmException e)
                {
                    throw new PGPException("can't find MD5 digest", e);
                }
                
                for (int i = 0; i != loopCount; i++)
                {
                    digest.update((byte)0);
                }
                
                digest.update(pBytes);
            }
                                
            byte[]    dig = digest.digest();
            
            if (dig.length > (keyBytes.length - generatedBytes))
            {
                System.arraycopy(dig, 0, keyBytes, generatedBytes, keyBytes.length - generatedBytes);
            }
            else
            {
                System.arraycopy(dig, 0, keyBytes, generatedBytes, dig.length);
            }
            
            generatedBytes += dig.length;
            
            loopCount++;
        }
        
        for (int i = 0; i != pBytes.length; i++)
        {
            pBytes[i] = 0;
        }

        return new SecretKeySpec(keyBytes, algName);
    }

    static MessageDigest getDigestInstance(
        String digestName, 
        Provider provider)
        throws NoSuchAlgorithmException
    {
        try
        {       
            return MessageDigest.getInstance(digestName, provider);
        }
        catch (NoSuchAlgorithmException e)
        {
            // try falling back
            return MessageDigest.getInstance(digestName);
        }
    }

    /**
     * write out the passed in file as a literal data packet.
     * 
     * @param out
     * @param fileType the LiteralData type for the file.
     * @param file
     * 
     * @throws IOException
     */
    public static void writeFileToLiteralData(
        OutputStream    out,
        char            fileType,
        File            file)
        throws IOException
    {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, file.getName(), file.length(), new Date(file.lastModified()));
        pipeFileContents(file, pOut, 4096);
    }
    
    /**
     * write out the passed in file as a literal data packet in partial packet format.
     * 
     * @param out
     * @param fileType the LiteralData type for the file.
     * @param file
     * @param buffer buffer to be used to chunk the file into partial packets.
     * 
     * @throws IOException
     */
    public static void writeFileToLiteralData(
        OutputStream    out,
        char            fileType,
        File            file,
        byte[]          buffer)
        throws IOException
    {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(out, fileType, file.getName(), new Date(file.lastModified()), buffer);
        pipeFileContents(file, pOut, buffer.length);
    }

    private static void pipeFileContents(File file, OutputStream pOut, int bufSize) throws IOException
    {
        FileInputStream in = new FileInputStream(file);
        byte[] buf = new byte[bufSize];

        int len;
        while ((len = in.read(buf)) > 0)
        {
            pOut.write(buf, 0, len);
        }

        pOut.close();
        in.close();
    }

    private static final int READ_AHEAD = 60;
    
    private static boolean isPossiblyBase64(
        int    ch)
    {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') 
                || (ch >= '0' && ch <= '9') || (ch == '+') || (ch == '/')
                || (ch == '\r') || (ch == '\n');
    }
    
    /**
     * Return either an ArmoredInputStream or a BCPGInputStream based on
     * whether the initial characters of the stream are binary PGP encodings or not.
     * 
     * @param in the stream to be wrapped
     * @return a BCPGInputStream
     * @throws IOException
     */
    public static InputStream getDecoderStream(
        InputStream    in) 
        throws IOException
    {
        if (!in.markSupported())
        {
            in = new BufferedInputStreamExt(in);
        }
        
        in.mark(READ_AHEAD);
        
        int    ch = in.read();
        

        if ((ch & 0x80) != 0)
        {
            in.reset();
        
            return in;
        }
        else
        {
            if (!isPossiblyBase64(ch))
            {
                in.reset();
        
                return new ArmoredInputStream(in);
            }
            
            byte[]  buf = new byte[READ_AHEAD];
            int     count = 1;
            int     index = 1;
            
            buf[0] = (byte)ch;
            while (count != READ_AHEAD && (ch = in.read()) >= 0)
            {
                if (!isPossiblyBase64(ch))
                {
                    in.reset();
                    
                    return new ArmoredInputStream(in);
                }
                
                if (ch != '\n' && ch != '\r')
                {
                    buf[index++] = (byte)ch;
                }
                
                count++;
            }
            
            in.reset();
        
            //
            // nothing but new lines, little else, assume regular armoring
            //
            if (count < 4)
            {
                return new ArmoredInputStream(in);
            }
            
            //
            // test our non-blank data
            //
            byte[]    firstBlock = new byte[8];
            
            System.arraycopy(buf, 0, firstBlock, 0, firstBlock.length);

            byte[]    decoded = Base64.decode(firstBlock);
            
            //
            // it's a base64 PGP block.
            //
            if ((decoded[0] & 0x80) != 0)
            {
                return new ArmoredInputStream(in, false);
            }
            
            return new ArmoredInputStream(in);
        }
    }

    static Provider getProvider(String providerName)
        throws NoSuchProviderException
    {
        Provider prov = Security.getProvider(providerName);

        if (prov == null)
        {
            throw new NoSuchProviderException("provider " + providerName + " not found.");
        }

        return prov;
    }
    
    static class BufferedInputStreamExt extends BufferedInputStream
    {
        BufferedInputStreamExt(InputStream input)
        {
            super(input);
        }

        public synchronized int available() throws IOException
        {
            int result = super.available();
            if (result < 0)
            {
                result = Integer.MAX_VALUE;
            }
            return result;
        }
    }
}
