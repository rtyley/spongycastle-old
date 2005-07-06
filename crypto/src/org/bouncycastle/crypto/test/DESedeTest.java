package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.DESedeWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
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

    private TestResult wrapTest(
        int     id,
        byte[]  kek,
        byte[]  iv,
        byte[]  in,
        byte[]  out)
    {
        Wrapper wrapper = new DESedeWrapEngine();

        wrapper.init(true, new ParametersWithIV(new KeyParameter(kek), iv));

        try
        {
            byte[]  cText = wrapper.wrap(in, 0, in.length);
            if (!Arrays.areEqual(cText, out))
            {
                return new SimpleTestResult(false, getName() + ": failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": failed wrap test exception " + e.toString());
        }

        wrapper.init(false, new KeyParameter(kek));

        try
        {
            byte[]  pText = wrapper.unwrap(out, 0, out.length);
            if (!Arrays.areEqual(pText, in))
            {
                return new SimpleTestResult(false, getName() + ": failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText)));
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": failed unwrap test exception " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public TestResult perform()
    {
        TestResult      result = super.perform();
        if (!result.isSuccessful())
        {
            return result;
        }

        byte[]  kek1 = Hex.decode("255e0d1c07b646dfb3134cc843ba8aa71f025b7c0838251f");
        byte[]  iv1 = Hex.decode("5dd4cbfc96f5453b");
        byte[]  in1 = Hex.decode("2923bf85e06dd6ae529149f1f1bae9eab3a7da3d860d3e98");
        byte[]  out1 = Hex.decode("690107618ef092b3b48ca1796b234ae9fa33ebb4159604037db5d6a84eb3aac2768c632775a467d4");
        result = wrapTest(1, kek1, iv1, in1, out1);
        if (!result.isSuccessful())
        {
            return result;
        }

        return new SimpleTestResult(true, getName() + ": Okay");
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
