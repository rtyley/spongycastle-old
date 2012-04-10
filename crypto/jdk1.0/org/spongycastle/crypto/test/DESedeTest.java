package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * DESede tester
 */
public class DESedeTest
    extends CipherTest
{
    static String   input1 = "4e6f77206973207468652074696d6520666f7220616c6c20";
    static String   input2 = "4e6f7720697320746865";

    static Test[]  tests =
            {
                new BlockCipherVectorTest(0, new DESedeEngine(),
                        new KeyParameter(Hex.decode("0123456789abcdef0123456789abcdef")),
                        input1, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
                new BlockCipherVectorTest(1, new DESedeEngine(),
                        new KeyParameter(Hex.decode("0123456789abcdeffedcba9876543210")),
                        input1, "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c"),
                new BlockCipherVectorTest(2, new DESedeEngine(),
                        new KeyParameter(Hex.decode("0123456789abcdef0123456789abcdef0123456789abcdef")),
                        input1, "3fa40e8a984d48156a271787ab8883f9893d51ec4b563b53"),
                new BlockCipherVectorTest(3, new DESedeEngine(),
                        new KeyParameter(Hex.decode("0123456789abcdeffedcba98765432100123456789abcdef")),
                        input1, "d80a0d8b2bae5e4e6a0094171abcfc2775d2235a706e232c")
            };

    DESedeTest()
    {
        super(tests);
    }

    public String getName()
    {
        return "DESede";
    }

    public static void main(
        String[]    args)
    {
        DESedeTest test = new DESedeTest();
        TestResult result = test.perform();

        System.out.println(result);
    }
}
