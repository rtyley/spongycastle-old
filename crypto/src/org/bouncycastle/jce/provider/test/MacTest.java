package org.bouncycastle.jce.provider.test;

import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * MAC tester - vectors from 
 * <a href=http://www.itl.nist.gov/fipspubs/fip81.htm>FIP 81</a> and 
 * <a href=http://www.itl.nist.gov/fipspubs/fip113.htm>FIP 113</a>.
 */
public class MacTest
    implements Test
{
    static byte[]   keyBytes = Hex.decode("0123456789abcdef");
    static byte[]   ivBytes = Hex.decode("1234567890abcdef");

    static byte[]   input = Hex.decode("37363534333231204e6f77206973207468652074696d6520666f7220");

    static byte[]   output1 = Hex.decode("f1d30f68");
    static byte[]   output2 = Hex.decode("58d2e77e");
    static byte[]   output3 = Hex.decode("cd647403");

    public MacTest()
    {
    }

    private boolean arraysEqual(
        byte[] a,
        byte[] b)
    {
        if (a.length != b.length)
        {
            return false;
        }

        for (int i = 0; i < a.length; i++)
        {
            if (a[i] != b[i]) return false;
        }

        return true;
    }

    public TestResult perform()
    {
        SecretKey           key = new SecretKeySpec(keyBytes, "DES");
        byte[]              out;
        Mac                 mac;

        try
        {
            mac = Mac.getInstance("DESMac", "BC");
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString());
        }

        //
        // standard DAC - zero IV
        //
        try
        {
            mac.init(key);
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString());
        }

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!arraysEqual(out, output1))
        {
            return new SimpleTestResult(false, getName() + ": Failed - expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // mac with IV.
        //
        try
        {
            mac.init(key, new IvParameterSpec(ivBytes));
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString());
        }

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!arraysEqual(out, output2))
        {
            return new SimpleTestResult(false, getName() + ": Failed - expected " + new String(Hex.encode(output2)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // CFB mac with IV - 8 bit CFB mode
        //
        try
        {
            mac = Mac.getInstance("DESMac/CFB8", "BC");

            mac.init(key, new IvParameterSpec(ivBytes));
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Failed - exception " + e.toString());
        }

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!arraysEqual(out, output3))
        {
            return new SimpleTestResult(false, getName() + ": Failed - expected " + new String(Hex.encode(output3)) + " got " + new String(Hex.encode(out)));
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public String getName()
    {
        return "Mac";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new MacTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
