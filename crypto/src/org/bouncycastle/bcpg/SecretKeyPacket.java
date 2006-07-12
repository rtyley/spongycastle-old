package org.bouncycastle.bcpg;

import java.io.*;

/**
 * basic packet for a PGP secret key
 */
public class SecretKeyPacket 
    extends ContainedPacket implements PublicKeyAlgorithmTags
{
    private PublicKeyPacket    pubKeyPacket;
    private byte[]             secKeyData;
    private int                stringToKey;
    private int                encAlgorithm;
    private S2K                s2k;
    private byte[]             iv;
    
    /**
     * 
     * @param in
     * @throws IOException
     */
    SecretKeyPacket(
        BCPGInputStream    in)
        throws IOException
    {      
        pubKeyPacket = new PublicKeyPacket(in);

        stringToKey = in.read();
        
        if (stringToKey == 0xff || stringToKey == 0xfe)
        {
            encAlgorithm = in.read();
            s2k = new S2K(in);
        }
        else
        {
            encAlgorithm = stringToKey;
        }

        if (!(s2k != null && s2k.getType() == S2K.GNU_DUMMY_S2K && s2k.getProtectionMode() == 0x01))
        {
            if (stringToKey != 0) 
            {
                if (encAlgorithm < 7)
                {
                    iv = new byte[8];
                }
                else
                {
                    iv = new byte[16];
                }
                in.readFully(iv, 0, iv.length);
            }
        }
        
        if (in.available() != 0)
        {
            secKeyData = new byte[in.available()];
            
            in.readFully(secKeyData);
        }
    }
    
    /**
     * 
     * @param pubKeyPacket
     * @param encAlgorithm
     * @param s2k
     * @param iv
     * @param secKeyData
     */
    public SecretKeyPacket(
        PublicKeyPacket pubKeyPacket,
        int             encAlgorithm,
        S2K             s2k,
        byte[]          iv,
        byte[]          secKeyData)
    {
        this.pubKeyPacket = pubKeyPacket;
        this.encAlgorithm = encAlgorithm;
        
        if (encAlgorithm != SymmetricKeyAlgorithmTags.NULL)
        {
            this.stringToKey = 0xff;
        }
        else
        {
            this.stringToKey = 0x00;
        }
        
        this.s2k = s2k;
        this.iv = iv;
        this.secKeyData = secKeyData;
    }
    
    public int getEncAlgorithm()
    {
        return encAlgorithm;
    }
    
    public byte[] getIV()
    {
        return iv;
    }
    
    public S2K getS2K()
    {
        return s2k;
    }
    
    public PublicKeyPacket getPublicKeyPacket()
    {
        return pubKeyPacket;
    }
    
    public byte[] getSecretKeyData()
    {
        return secKeyData;
    }
    
    public byte[] getEncodedContents()
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);
        
        pOut.write(pubKeyPacket.getEncodedContents());
        
        pOut.write(stringToKey);

        if (stringToKey == 0xff || stringToKey == 0xfe)
        {
            pOut.write(encAlgorithm);
            pOut.writeObject(s2k);
        }
        
        if (iv != null)
        {
            pOut.write(iv);
        }
        
        if (secKeyData != null)
        {
            pOut.write(secKeyData);
        }
        
        return bOut.toByteArray();
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(SECRET_KEY, getEncodedContents(), true);
    }
}
