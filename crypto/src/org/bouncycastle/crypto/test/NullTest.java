package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.NullEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class NullTest 
    extends CipherTest
{
    static Test[]  tests = 
    {
        new BlockCipherVectorTest(0, new AESEngine(),
                new KeyParameter(Hex.decode("00")), "00", "00")
    };
    
    NullTest()
    {
        super(tests);
    }

    public String getName()
    {
        return "Null";
    }

    public TestResult perform()
    {
        BlockCipher engine = new NullEngine();
        
        engine.init(true, null);
        
        byte[] buf = new byte[1];
        
        engine.processBlock(buf, 0, buf, 0);
        
        if (buf[0] != 0)
        {
            return new SimpleTestResult(false, getName() + ": NullCipher changed data!");
        }
        
        byte[] shortBuf = new byte[0];
        
        try
        {   
            engine.processBlock(shortBuf, 0, buf, 0);
            
            return new SimpleTestResult(false, getName() + ": failed short input check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        try
        {   
            engine.processBlock(buf, 0, shortBuf, 0);
            
            return new SimpleTestResult(false, getName() + ": failed short output check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public static void main(
        String[]    args)
    {
        NullTest    test = new NullTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
