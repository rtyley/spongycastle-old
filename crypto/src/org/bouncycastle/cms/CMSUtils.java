package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;

class CMSUtils
{
    private static Runtime RUNTIME = Runtime.getRuntime();
    
    static int getMaximumMemory()
    {
        long maxMem = RUNTIME.maxMemory();
        
        if (maxMem > Integer.MAX_VALUE)
        {
            return Integer.MAX_VALUE;
        }
        
        return (int)maxMem;
    }
    
    static ContentInfo readContentInfo(
        byte[] input)
        throws CMSException
    {
        // enforce limit checking as from a byte array
        return readContentInfo(new ASN1InputStream(input));
    }

    static ContentInfo readContentInfo(
        InputStream input)
        throws CMSException
    {
        // enforce some limit checking
        return readContentInfo(new ASN1InputStream(input, getMaximumMemory()));
    } 
    
    private static ContentInfo readContentInfo(
        ASN1InputStream in)
        throws CMSException
    {
        try
        {
            return ContentInfo.getInstance(in.readObject());
        }
        catch (IOException e)
        {
            throw new CMSException("IOException reading content.", e);
        }
        catch (ClassCastException e)
        {
            throw new CMSException("Malformed content.", e);
        }
        catch (IllegalArgumentException e)
        {
            throw new CMSException("Malformed content.", e);
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
