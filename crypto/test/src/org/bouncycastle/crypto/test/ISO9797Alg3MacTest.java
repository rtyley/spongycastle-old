package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class ISO9797Alg3MacTest
    extends SimpleTest
{
    static byte[]   keyBytes = Hex.decode("7CA110454A1A6E570131D9619DC1376E");
    static byte[]   ivBytes = Hex.decode("0000000000000000");

    static byte[]   input1 = "Hello World !!!!".getBytes(); 
        
    static byte[]   output1 = Hex.decode("F09B856213BAB83B");

    public ISO9797Alg3MacTest()
    {
    }

    public void performTest()
    {
        KeyParameter        key = new KeyParameter(keyBytes);
        BlockCipher         cipher = new DESEngine();
        Mac                 mac = new ISO9797Alg3Mac(cipher);

        //
        // standard DAC - zero IV
        //
        mac.init(key);

        mac.update(input1, 0, input1.length);

        byte[]  out = new byte[8];

        mac.doFinal(out, 0);

        if (!areEqual(out, output1))
        {
            fail("Failed - expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        //  reset
        //
        mac.reset();
        
        mac.init(key);
        
        for (int i = 0; i != input1.length / 2; i++)
        {
            mac.update(input1[i]);
        }
        
        mac.update(input1, input1.length / 2, input1.length - (input1.length / 2));
        
        mac.doFinal(out, 0);

        if (!areEqual(out, output1))
        {
            fail("Reset failed - expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
        }
    }

    public String getName()
    {
        return "ISO9797Alg3Mac";
    }

    public static void main(
        String[]    args)
    {
        runTest(new ISO9797Alg3MacTest());
    }
}

