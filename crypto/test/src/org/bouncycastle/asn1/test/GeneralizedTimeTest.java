package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

import java.text.SimpleDateFormat;
import java.util.SimpleTimeZone;

/**
 * X.690 test example
 */
public class GeneralizedTimeTest
    implements Test
{
    String[] input =
        {
            "20020122122220",
            "20020122122220Z",
            "20020122122220-1000",
            "20020122122220+00",
            "20020122122220.1",
            "20020122122220.1Z",
            "20020122122220.1-1000",
            "20020122122220.1+00",
            "20020122122220.01",
            "20020122122220.01Z",
            "20020122122220.01-1000",
            "20020122122220.01+00",
            "20020122122220.001",
            "20020122122220.001Z",
            "20020122122220.001-1000",
            "20020122122220.001+00",
            "20020122122220.0001",
            "20020122122220.0001Z",
            "20020122122220.0001-1000",
            "20020122122220.0001+00",
            "20020122122220.0001+1000"
        };

    String[] output = {
            "20020122122220",
            "20020122122220GMT+00:00",
            "20020122122220GMT-10:00",
            "20020122122220GMT+00:00",
            "20020122122220.1",
            "20020122122220.1GMT+00:00",
            "20020122122220.1GMT-10:00",
            "20020122122220.1GMT+00:00",
            "20020122122220.01",
            "20020122122220.01GMT+00:00",
            "20020122122220.01GMT-10:00",
            "20020122122220.01GMT+00:00",
            "20020122122220.001",
            "20020122122220.001GMT+00:00",
            "20020122122220.001GMT-10:00",
            "20020122122220.001GMT+00:00",
            "20020122122220.0001",
            "20020122122220.0001GMT+00:00",
            "20020122122220.0001GMT-10:00",
            "20020122122220.0001GMT+00:00",
            "20020122122220.0001GMT+10:00" };

    String[] zOutput = {
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122122220Z",
            "20020122222220Z",
            "20020122122220Z",
            "20020122022220Z"
    };

    public String getName()
    {
        return "GeneralizedTime";
    }
    
    public TestResult perform()
    {
        try
        {
            SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmss'Z'");

            dateF.setTimeZone(new SimpleTimeZone(0,"Z"));

            for (int i = 0; i != input.length; i++)
            {
                DERGeneralizedTime    t = new DERGeneralizedTime(input[i]);

                if (!t.getTime().equals(output[i]))
                {
                    return new SimpleTestResult(false, getName() + ": failed conversion test");
                }

                if (output[i].indexOf('G') > 0)   // don't try checking local time
                {
                    if (!dateF.format(t.getDate()).equals(zOutput[i]))
                    {
                        return new SimpleTestResult(false, getName() + ": failed date conversion test");
                    }
                }
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Exception - " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        Test    test = new GeneralizedTimeTest();

        TestResult  result = test.perform();

        System.out.println(result);
    }
}
