package org.bouncycastle.crypto.test;

import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 */
public abstract class CipherTest
    implements Test
{
    Test[]      tests;

    protected CipherTest(
        Test[]  tests)
    {
        this.tests = tests;
    }

    public abstract String getName();

    public TestResult perform()
    {
        for (int i = 0; i != tests.length; i++)
        {
            TestResult  res = tests[i].perform();

            if (!res.isSuccessful())
            {
                return res;
            }
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }
}
