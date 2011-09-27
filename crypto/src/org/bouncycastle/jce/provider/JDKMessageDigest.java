package org.bouncycastle.jce.provider;

import java.security.MessageDigest;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;

public class JDKMessageDigest
    extends MessageDigest
{
    Digest  digest;

    protected JDKMessageDigest(
        Digest  digest)
    {
        super(digest.getAlgorithmName());

        this.digest = digest;
    }

    public void engineReset() 
    {
        digest.reset();
    }

    public void engineUpdate(
        byte    input) 
    {
        digest.update(input);
    }

    public void engineUpdate(
        byte[]  input,
        int     offset,
        int     len) 
    {
        digest.update(input, offset, len);
    }

    public byte[] engineDigest() 
    {
        byte[]  digestBytes = new byte[digest.getDigestSize()];

        digest.doFinal(digestBytes, 0);

        return digestBytes;
    }
    
    static public class Tiger
        extends JDKMessageDigest
        implements Cloneable
    {
        public Tiger()
        {
            super(new TigerDigest());
        }

        public Object clone()
            throws CloneNotSupportedException
        {
            Tiger d = (Tiger)super.clone();
            d.digest = new TigerDigest((TigerDigest)digest);

            return d;
        }
    }
    
    static public class GOST3411
        extends JDKMessageDigest
        implements Cloneable
    {
        public GOST3411()
        {
            super(new GOST3411Digest());
        }
    
        public Object clone()
        throws CloneNotSupportedException
        {
            GOST3411 d = (GOST3411)super.clone();
            d.digest = new GOST3411Digest((GOST3411Digest)digest);

            return d;
        }
    }
    
    static public class Whirlpool
       extends JDKMessageDigest
       implements Cloneable
    {
        public Whirlpool()
        {
            super(new WhirlpoolDigest());
        }
        
        public Object clone()
        throws CloneNotSupportedException
        {
            Whirlpool d = (Whirlpool)super.clone();
            d.digest = new WhirlpoolDigest((WhirlpoolDigest)digest);
            
            return d;
        }
    }
}
