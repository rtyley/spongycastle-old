package org.spongycastle.crypto.test;

import org.spongycastle.crypto.engines.RC4Engine;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.util.test.SimpleTestResult;
import org.spongycastle.util.test.Test;
import org.spongycastle.util.test.TestResult;

/**
 * RC4 Test
 */
public class RC4Test
    implements Test
{
    StreamCipherVectorTest[] tests =
    {
        new StreamCipherVectorTest(0, new RC4Engine(),
                new KeyParameter(Hex.decode("0123456789ABCDEF")),
                "4e6f772069732074", "3afbb5c77938280d"),
        new StreamCipherVectorTest(0, new RC4Engine(),
                new KeyParameter(Hex.decode("0123456789ABCDEF")),
                "68652074696d6520", "1cf1e29379266d59"),
        new StreamCipherVectorTest(0, new RC4Engine(),
                new KeyParameter(Hex.decode("0123456789ABCDEF")),
                "666f7220616c6c20", "12fbb0c771276459")
    };

    public String getName()
    {
        return "RC4";
    }

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

    public static void main(
        String[]    args)
    {
        RC4Test test = new RC4Test();
        TestResult  result = test.perform();

        System.out.println(result);
    }
}
