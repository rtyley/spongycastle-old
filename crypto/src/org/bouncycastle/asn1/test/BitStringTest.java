package org.bouncycastle.asn1.test;

import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.asn1.x509.KeyUsage;

public class BitStringTest
    implements Test
{
    public TestResult perform()
    {
        KeyUsage k = new KeyUsage(KeyUsage.digitalSignature);
        if ((k.getBytes()[0] != (byte)KeyUsage.digitalSignature) || (k.getPadBits() != 7))
        {
            return new SimpleTestResult(false, getName() + ": failed digitalSignature");
        }
        
        k = new KeyUsage(KeyUsage.nonRepudiation);
        if ((k.getBytes()[0] != (byte)KeyUsage.nonRepudiation) || (k.getPadBits() != 6))
        {
            return new SimpleTestResult(false, getName() + ": failed nonRepudiation");
        }
        
        k = new KeyUsage(KeyUsage.keyEncipherment);
        if ((k.getBytes()[0] != (byte)KeyUsage.keyEncipherment) || (k.getPadBits() != 5))
        {
            return new SimpleTestResult(false, getName() + ": failed keyEncipherment");
        }
        
        k = new KeyUsage(KeyUsage.cRLSign);
        if ((k.getBytes()[0] != (byte)KeyUsage.cRLSign)  || (k.getPadBits() != 1))
        {
            return new SimpleTestResult(false, getName() + ": failed cRLSign");
        }
        
        k = new KeyUsage(KeyUsage.decipherOnly);
        if ((k.getBytes()[1] != (byte)(KeyUsage.decipherOnly >> 8))  || (k.getPadBits() != 7))
        {
            return new SimpleTestResult(false, getName() + ": failed decipherOnly");
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "BitString";
    }

    public static void main(
        String[] args)
    {
        BitStringTest    test = new BitStringTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
