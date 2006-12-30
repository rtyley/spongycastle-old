package org.bouncycastle.cms;

import javax.crypto.interfaces.PBEKey;

public abstract class CMSPBEKey
    implements PBEKey
{
    private char[] password;
    private byte[] salt;
    private int    iterationCount;

    public CMSPBEKey(char[] password, byte[] salt, int iterationCount)
    {
        this.password = password;
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    public char[] getPassword()
    {
        return password;
    }

    public byte[] getSalt()
    {
        return salt;
    }

    public int getIterationCount()
    {
        return iterationCount;
    }

    public String getAlgorithm()
    {
        return "PKCS5S2";
    }

    public String getFormat()
    {
        return "RAW";
    }

    public byte[] getEncoded()
    {
        return null;
    }

    abstract byte[] getEncoded(String algorithmOid);
}
