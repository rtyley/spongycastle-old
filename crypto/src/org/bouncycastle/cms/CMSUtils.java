package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

class CMSUtils
{
    /**
     * Return the digest algorithm using one of the standard JCA string
     * representations rather the the algorithm identifier (if possible).
     */
    static String getDigestAlgName(
        String digestAlgOID)
    {   
        if (PKCSObjectIdentifiers.md5.getId().equals(digestAlgOID))
        {
            return "MD5";
        }
        else if (OIWObjectIdentifiers.idSHA1.getId().equals(digestAlgOID))
        {
            return "SHA1";
        }
        else if (NISTObjectIdentifiers.id_sha224.getId().equals(digestAlgOID))
        {
            return "SHA224";
        }
        else if (NISTObjectIdentifiers.id_sha256.getId().equals(digestAlgOID))
        {
            return "SHA256";
        }
        else if (NISTObjectIdentifiers.id_sha384.getId().equals(digestAlgOID))
        {
            return "SHA384";
        }
        else if (NISTObjectIdentifiers.id_sha512.getId().equals(digestAlgOID))
        {
            return "SHA512";
        }
        else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA1";
        }
        else if (PKCSObjectIdentifiers.sha224WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA224";
        }
        else if (PKCSObjectIdentifiers.sha256WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA256";
        }
        else if (PKCSObjectIdentifiers.sha384WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA384";
        }
        else if (PKCSObjectIdentifiers.sha512WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA512";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd128.getId().equals(digestAlgOID))
        {
            return "RIPEMD128";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd160.getId().equals(digestAlgOID))
        {
            return "RIPEMD160";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd256.getId().equals(digestAlgOID))
        {
            return "RIPEMD256";
        }
        else if (CryptoProObjectIdentifiers.gostR3411.getId().equals(digestAlgOID))
        {
            return "GOST3411";
        }
        else
        {
            return digestAlgOID;            
        }
    }
    
    /**
     * Return the digest encryption algorithm using one of the standard
     * JCA string representations rather the the algorithm identifier (if
     * possible).
     */
    static String getEncryptionAlgName(
        String encryptionAlgOID)
    {
        if (X9ObjectIdentifiers.id_dsa_with_sha1.getId().equals(encryptionAlgOID))
        {
            return "DSA";
        }
        else if (PKCSObjectIdentifiers.rsaEncryption.getId().equals(encryptionAlgOID))
        {
            return "RSA";
        }
        else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.equals(encryptionAlgOID))
        {
            return "RSA";
        }
        else if (TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm.equals(encryptionAlgOID))
        {
            return "RSA";
        }
        else if (CryptoProObjectIdentifiers.gostR3410_94.getId().equals(encryptionAlgOID))
        {
            return "GOST3410";
        }
        else if (CryptoProObjectIdentifiers.gostR3410_2001.getId().equals(encryptionAlgOID))
        {
            return "ECGOST3410";
        }
        else
        {
            return encryptionAlgOID;            
        }
    }
    
    public static byte[] streamToByteArray(
        InputStream in) 
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        int ch;
        
        while ((ch = in.read()) >= 0)
        {
            bOut.write(ch);
        }
        
        return bOut.toByteArray();
    }
}
