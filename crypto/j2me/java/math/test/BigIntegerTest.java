package java.math.test;

import java.math.BigInteger;

import java.security.SecureRandom;
import org.bouncycastle.util.test.*;


public class BigIntegerTest
    implements Test
{
    public String getName()
    {
        return "BigInteger";
    }

    private boolean arrayEquals(byte[] a, byte[] b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i != a.length; i++)
        {
            if (a[i] != b[i])
            {
                return false;
            }
        }

        return true;
    }

    public TestResult perform()
    {
    BigInteger n1, n2, r1;

    // test division where the difference in bit length of the dividend and divisor is 32 bits 
        n1 = new BigInteger("54975581388");
        n2 = new BigInteger("10");
        r1 = n1.divide(n2);
        if (!r1.toString(10).equals("5497558138"))
        {
                return new SimpleTestResult(false, "BigInteger: failed Divide Test");
        }

        // two's complement test
        byte[] zeroBytes = BigInteger.ZERO.toByteArray();
        byte[] oneBytes = BigInteger.ONE.toByteArray();
        byte[] minusOneBytes = BigInteger.ONE.negate().toByteArray();
    
        BigInteger zero = new BigInteger(zeroBytes);
        if (!zero.equals(BigInteger.ZERO))
        {
            return new SimpleTestResult(false, "Failed constructing zero");
        }

        BigInteger one = new BigInteger(oneBytes);
        if (!one.equals(BigInteger.ONE))
        {
            return new SimpleTestResult(false, "Failed constructing one");
        }

        BigInteger minusOne = new BigInteger(minusOneBytes);
        if (!minusOne.equals(BigInteger.ONE.negate()))
        {
            return new SimpleTestResult(false, "Failed constructing minus one");
        }
    
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[100];
        for (int i=0; i < 100; i++)
        {
            random.nextBytes(randomBytes);
            BigInteger bcInt = new BigInteger(randomBytes);
            BigInteger bcInt2 = new BigInteger(bcInt.toByteArray());
            if (!bcInt.equals(bcInt2))
            {
                return new SimpleTestResult(false, "Failed constructing random value " + i);
            }
            
//            java.math.BigInteger jdkInt = new java.math.BigInteger(randomBytes);
//            byte[] bcBytes = bcInt.toByteArray();
//            byte[] jdkBytes = jdkInt.toByteArray();
//            if (!arrayEquals(bcBytes, jdkBytes))
//            {
//                return new SimpleTestResult(false, "Failed constructing random value " + i);
//            }
        }
    
        return new SimpleTestResult(true, "BigInteger: Okay");
    }

    public static void main(
        String[]    args)
    {
        BigIntegerTest         test = new BigIntegerTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}

