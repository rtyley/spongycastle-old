package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 */
public abstract class CipherTest
    implements Test
{
    private Test[]      _tests;
    private BlockCipher _engine;
    private KeyParameter _validKey;

    protected CipherTest(
        Test[]  tests)
    {
        _tests = tests;
    }

    protected CipherTest(
        Test[]       tests,
        BlockCipher  engine,
        KeyParameter validKey)
    {
        _tests = tests;
        _engine = engine;
        _validKey = validKey;
    }
    
    public abstract String getName();

    public TestResult perform()
    {
        for (int i = 0; i != _tests.length; i++)
        {
            TestResult  res = _tests[i].perform();

            if (!res.isSuccessful())
            {
                return res;
            }
        }

        if (_engine != null)
        {
            //
            // state tests
            //
            byte[]      buf = new byte[16];
            
            try
            {   
                _engine.processBlock(buf, 0, buf, 0);
                
                return new SimpleTestResult(false, getName() + ": failed initialisation check");
            }
            catch (IllegalStateException e)
            {
                // expected 
            }
            
            return bufferSizeCheck((_engine));
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    private TestResult bufferSizeCheck(
        BlockCipher engine)
    {
        byte[] correctBuf = new byte[engine.getBlockSize()];
        byte[] shortBuf = new byte[correctBuf.length / 2];
        
        engine.init(true, _validKey);
        
        try
        {   
            engine.processBlock(shortBuf, 0, correctBuf, 0);
            
            return new SimpleTestResult(false, getName() + ": failed short input check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        try
        {   
            engine.processBlock(correctBuf, 0, shortBuf, 0);
            
            return new SimpleTestResult(false, getName() + ": failed short output check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        engine.init(false, _validKey);
        
        try
        {   
            engine.processBlock(shortBuf, 0, correctBuf, 0);
            
            return new SimpleTestResult(false, getName() + ": failed short input check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        try
        {   
            engine.processBlock(correctBuf, 0, shortBuf, 0);
            
            return new SimpleTestResult(false, getName() + ": failed short output check");
        }
        catch (DataLengthException e)
        {
            // expected 
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
}
