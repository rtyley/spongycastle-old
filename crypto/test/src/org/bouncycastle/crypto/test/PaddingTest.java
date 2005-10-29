package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.TBCPadding;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * General Padding tests.
 */
public class PaddingTest
    implements Test
{
    public PaddingTest()
    {
    }

    private boolean isEqualTo(
        byte[]  a,
        byte[]  b)
    {
        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    private TestResult blockCheck(
        PaddedBufferedBlockCipher   cipher,
        BlockCipherPadding          padding,
        KeyParameter                key,
        byte[]                      data)
    {
        byte[]  out = new byte[data.length + 8];
        byte[]  dec = new byte[data.length];
        
        try
        {                
            cipher.init(true, key);
            
            int    len = cipher.processBytes(data, 0, data.length, out, 0);
            
            len += cipher.doFinal(out, len);
            
            cipher.init(false, key);
            
            int    decLen = cipher.processBytes(out, 0, len, dec, 0);
            
            decLen += cipher.doFinal(dec, decLen);
            
            if (!isEqualTo(data, dec))
            {
                return new SimpleTestResult(false, getName() + ": failed to decrypt - i = " + data.length + ", padding = " + padding.getPaddingName());
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Exception - " + e.toString(), e);
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult testPadding(
        BlockCipherPadding  padding,
        SecureRandom        rand,
        byte[]              ffVector,
        byte[]              ZeroVector)
    {
        PaddedBufferedBlockCipher    cipher = new PaddedBufferedBlockCipher(new DESEngine(), padding);
        KeyParameter                 key = new KeyParameter(Hex.decode("0011223344556677"));
        
        //
        // ff test
        //
        byte[]    data = { (byte)0xff, (byte)0xff, (byte)0xff, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0 };
        
        if (ffVector != null)
        {
            padding.addPadding(data, 3);
            
            if (!isEqualTo(data, ffVector))
            {
                return new SimpleTestResult(false, getName() + ": failed ff test for " + padding.getPaddingName());
            }
        }
        
        //
        // zero test
        //
        if (ZeroVector != null)
        {
            data = new byte[8];
            padding.addPadding(data, 4);
            
            if (!isEqualTo(data, ZeroVector))
            {
                return new SimpleTestResult(false, getName() + ": failed zero test for " + padding.getPaddingName());
            }
        }
        
        for (int i = 1; i != 200; i++)
        {
            data = new byte[i];
            
            rand.nextBytes(data);

            TestResult result = blockCheck(cipher, padding, key, data);
            if (!result.isSuccessful())
            {
                return result;
            }
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult perform()
    {
        SecureRandom    rand = new SecureRandom(new byte[20]);
        
        rand.setSeed(System.currentTimeMillis());
        
        TestResult    res = testPadding(new PKCS7Padding(), rand,
                                    Hex.decode("ffffff0505050505"),
                                    Hex.decode("0000000004040404"));
        if (!res.isSuccessful())
        {
            return res;
        }

        res = testPadding(new ISO10126d2Padding(), rand,
                                    null,
                                    null);
        if (!res.isSuccessful())
        {
            return res;
        }
        
        res = testPadding(new X923Padding(), rand,
                                    null,
                                    null);
        if (!res.isSuccessful())
        {
            return res;
        }

        res = testPadding(new TBCPadding(), rand,
                                    Hex.decode("ffffff0000000000"),
                                    Hex.decode("00000000ffffffff"));
        if (!res.isSuccessful())
        {
            return res;
        }
        
        res = testPadding(new ZeroBytePadding(), rand,
                                    Hex.decode("ffffff0000000000"),
                                    null);
        if (!res.isSuccessful())
        {
            return res;
        }
        
        res = testPadding(new ISO7816d4Padding(), rand,
                                    Hex.decode("ffffff8000000000"),
                                    Hex.decode("0000000080000000"));
        if (!res.isSuccessful())
        {
            return res;
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "PaddingTest";
    }

    public static void main(
        String[]    args)
    {
        PaddingTest    test = new PaddingTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
