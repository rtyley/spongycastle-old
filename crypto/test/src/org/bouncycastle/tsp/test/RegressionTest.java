package org.bouncycastle.tsp.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class RegressionTest
{
    public static Test[]    tests = {
        new TSPTest(),
        new ParseTest()
    };

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());
        
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  result = tests[i].perform();
            System.out.println(result);
        }
    }
}

