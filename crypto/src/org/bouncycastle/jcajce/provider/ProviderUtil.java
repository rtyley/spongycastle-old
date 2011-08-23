package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

public class ProviderUtil
{
    private static final long  MAX_MEMORY = Runtime.getRuntime().maxMemory();

    public static int getReadLimit(InputStream in)
        throws IOException
    {
        if (in instanceof ByteArrayInputStream)
        {
            return in.available();
        }

        if (MAX_MEMORY > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }

        return (int)MAX_MEMORY;
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, ASN1Encodable keyData)
    {
        try
        {
            return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(AlgorithmIdentifier algId, byte[] keyData)
    {
        try
        {
            return getEncodedSubjectPublicKeyInfo(new SubjectPublicKeyInfo(algId, keyData));
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public static byte[] getEncodedSubjectPublicKeyInfo(SubjectPublicKeyInfo info)
    {
         try
         {
             return info.getEncoded(ASN1Encoding.DER);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    public static byte[] getEncodedPrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privKey)
    {
         try
         {
             PrivateKeyInfo info = new PrivateKeyInfo(algId, privKey.toASN1Object());

             return getEncodedPrivateKeyInfo(info);
         }
         catch (Exception e)
         {
             return null;
         }
    }

    public static byte[] getEncodedPrivateKeyInfo(PrivateKeyInfo info)
    {
         try
         {
             return info.getEncoded(ASN1Encoding.DER);
         }
         catch (Exception e)
         {
             return null;
         }
    }
//
//    public static ECParameterSpec getEcImplicitlyCa()
//    {
//        return null;
//    }
}
