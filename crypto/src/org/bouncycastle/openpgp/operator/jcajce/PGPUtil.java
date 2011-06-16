package org.bouncycastle.openpgp.operator.jcajce;

import java.io.IOException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.MPInteger;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;

/**
 * Basic utility class
 */
class PGPUtil
    implements HashAlgorithmTags
{
    private    static String    defProvider = "BC";


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
        case HashAlgorithmTags.TIGER_192:
            return "TIGER";
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
            throw new IllegalArgumentException("unknown symmetric algorithm: " + algorithm);
        }
    }
    
    public static SecretKey makeSymmetricKey(
        int             algorithm,
        byte[]          keyBytes)
        throws PGPException
    {
        String    algName = null;
        
        switch (algorithm)
        {
        case SymmetricKeyAlgorithmTags.TRIPLE_DES:
            algName = "DES_EDE";
            break;
        case SymmetricKeyAlgorithmTags.IDEA:
            algName = "IDEA";
            break;
        case SymmetricKeyAlgorithmTags.CAST5:
            algName = "CAST5";
            break;
        case SymmetricKeyAlgorithmTags.BLOWFISH:
            algName = "Blowfish";
            break;
        case SymmetricKeyAlgorithmTags.SAFER:
            algName = "SAFER";
            break;
        case SymmetricKeyAlgorithmTags.DES:
            algName = "DES";
            break;
        case SymmetricKeyAlgorithmTags.AES_128:
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.AES_192:
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.AES_256:
            algName = "AES";
            break;
        case SymmetricKeyAlgorithmTags.TWOFISH:
            algName = "Twofish";
            break;
        default:
            throw new PGPException("unknown symmetric algorithm: " + algorithm);
        }

        return new SecretKeySpec(keyBytes, algName);
    }
}
