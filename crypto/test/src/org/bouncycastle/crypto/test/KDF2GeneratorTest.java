package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.ShortenedDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * KDF2 tests - vectors from ISO 18033.
 */
public class KDF2GeneratorTest
    extends SimpleTest
{
    private byte[] seed1 = Hex.decode("d6e168c5f256a2dcff7ef12facd390f393c7a88d");
    private byte[] mask1 = Hex.decode(
            "df79665bc31dc5a62f70535e52c53015b9d37d412ff3c119343959"
          + "9e1b628774c50d9ccb78d82c425e4521ee47b8c36a4bcffe8b8112a8"
          + "9312fc04420a39de99223890e74ce10378bc515a212b97b8a6447ba6"
          + "a8870278f0262727ca041fa1aa9f7b5d1cf7f308232fe861");
    
    private byte[] seed2 = Hex.decode(
             "032e45326fa859a72ec235acff929b15d1372e30b207255f0611b8f785d7643741" 
           + "52e0ac009e509e7ba30cd2f1778e113b64e135cf4e2292c75efe5288edfda4");
    private byte[] mask2 = Hex.decode(
             "10a2403db42a8743cb989de86e668d168cbe604611ac179f819a3d18412e9eb456" 
           + "68f2923c087c12fee0c5a0d2a8aa70185401fbbd99379ec76c663e875a60b4aacb13"
           + "19fa11c3365a8b79a44669f26fb555c80391847b05eca1cb5cf8c2d531448d33fbac"
           + "a19f6410ee1fcb260892670e0814c348664f6a7248aaf998a3acc6");


    public KDF2GeneratorTest()
    {
    }
    
    public void performTest()
    {
        checkMask(1, new KDF2BytesGenerator(new ShortenedDigest(new SHA256Digest(), 20)), seed1, mask1);
        checkMask(2, new KDF2BytesGenerator(new ShortenedDigest(new SHA256Digest(), 20)), seed2, mask2);
        
        try
        {
            new KDF2BytesGenerator(new SHA1Digest()).generateBytes(new byte[10], 0, 20);
            
            fail("short input array not caught");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
    }
    
    private void checkMask(
        int                count,
        DerivationFunction kdf,
        byte[]             seed,
        byte[]             result)
    {
        byte[]             data = new byte[result.length];
        
        kdf.init(new KDFParameters(seed, new byte[0]));
        
        kdf.generateBytes(data, 0, data.length);
        
        if (!areEqual(result, data))
        {
            fail("KDF2 failed generator test " + count);
        }
    }

    public String getName()
    {
        return "KDF2";
    }

    public static void main(
        String[]    args)
    {
        runTest(new KDF2GeneratorTest());
    }
}
