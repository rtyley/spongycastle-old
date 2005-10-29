package org.bouncycastle.jce.provider.test;

import java.security.Security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * MAC tester - vectors from 
 * <a href=http://www.itl.nist.gov/fipspubs/fip81.htm>FIP 81</a> and 
 * <a href=http://www.itl.nist.gov/fipspubs/fip113.htm>FIP 113</a>.
 */
public class MacTest
    extends SimpleTest
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

    public void performTest()
        throws Exception
    {
        SecretKey           key = new SecretKeySpec(keyBytes, "DES");
        byte[]              out;
        Mac                 mac;

        mac = Mac.getInstance("DESMac", "BC");

        //
        // standard DAC - zero IV
        //
        mac.init(key);

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!areEqual(out, output1))
        {
            fail("Failed - expected " + new String(Hex.encode(output1)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // mac with IV.
        //
        mac.init(key, new IvParameterSpec(ivBytes));

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!areEqual(out, output2))
        {
            fail("Failed - expected " + new String(Hex.encode(output2)) + " got " + new String(Hex.encode(out)));
        }
        
        //
        // CFB mac with IV - 8 bit CFB mode
        //
        mac = Mac.getInstance("DESMac/CFB8", "BC");

        mac.init(key, new IvParameterSpec(ivBytes));

        mac.update(input, 0, input.length);

        out = mac.doFinal();

        if (!areEqual(out, output3))
        {
            fail("Failed - expected " + new String(Hex.encode(output3)) + " got " + new String(Hex.encode(out)));
        }
    }

    public String getName()
    {
        return "Mac";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new MacTest());
    }
}
