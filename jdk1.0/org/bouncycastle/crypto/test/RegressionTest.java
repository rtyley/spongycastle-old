package org.spongycastle.crypto.test;

import org.spongycastle.util.test.Test;
import org.spongycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new AESTest(),
        new DESTest(),
        new DESedeTest(),
        new SkipjackTest(),
        new BlowfishTest(),
        new IDEATest(),
        new RC2Test(),
        new RC4Test(),
        new RC5Test(),
        new RC6Test(),
        new RijndaelTest(),
        new ECTest(),
        new RSATest()
    };

    public static void main(
        String[]    args)
    {
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            System.out.println(result);
        }
    }
}

