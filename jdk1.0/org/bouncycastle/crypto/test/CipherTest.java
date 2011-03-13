package org.spongycastle.crypto.test;

import org.spongycastle.util.test.SimpleTestResult;
import org.spongycastle.util.test.Test;
import org.spongycastle.util.test.TestResult;

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
