package org.bouncycastle.jce.provider.test;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * HMAC tester
 */
public class HMacTest
    extends SimpleTest
{
    static byte[]   keyBytes = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    static byte[]   message = "Hi There".getBytes();
    static byte[]   output1 = Hex.decode("b617318655057264e28bc0b6fb378c8ef146be00");
    static byte[]   output2 = Hex.decode("5ccec34ea9656392457fa1ac27f08fbc");
    static byte[]   output224 = Hex.decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
    static byte[]   output256 = Hex.decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    static byte[]   output384 = Hex.decode("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
    static byte[]   output512 = Hex.decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    static byte[]   outputOld384 = Hex.decode("0a046aaa0255e432912228f8ccda437c8a8363fb160afb0570ab5b1fd5ddc20eb1888b9ed4e5b6cb5bc034cd9ef70e40");
    static byte[]   outputOld512 = Hex.decode("9656975ee5de55e75f2976ecce9a04501060b9dc22a6eda2eaef638966280182477fe09f080b2bf564649cad42af8607a2bd8d02979df3a980f15e2326a0a22a");
    
    public HMacTest()
    {
    }

    public void testHMac(
        String  hmacName,
        byte[]  output)
        throws Exception
    {
        SecretKey           key = new SecretKeySpec(keyBytes, hmacName);
        byte[]              out;
        Mac                 mac;

        mac = Mac.getInstance(hmacName, "BC");

        mac.init(key);

        mac.reset();
        
        mac.update(message, 0, message.length);

        out = mac.doFinal();

        if (!areEqual(out, output))
        {
            fail("Failed - expected " + new String(Hex.encode(output)) + " got " + new String(Hex.encode(out)));
        }
        
        // no key generator for the old algorithms
        if (hmacName.startsWith("Old"))
        {
            return;
        }

        KeyGenerator kGen = KeyGenerator.getInstance(hmacName, "BC");
        
        mac.init(kGen.generateKey());
        
        mac.update(message);
        
        out = mac.doFinal();
    }

    private void testExceptions()
        throws Exception
    {
        Mac mac = null;
        
        mac = Mac.getInstance("HmacSHA1", "BC");
        
        byte [] b = {(byte)1, (byte)2, (byte)3, (byte)4, (byte)5};
        SecretKeySpec sks = new SecretKeySpec(b, "HmacSHA1");
        RC5ParameterSpec algPS = new RC5ParameterSpec(100, 100, 100);

        try
        {
            mac.init(sks, algPS);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // ignore okay
        }
        
        try
        {
            mac.init(null, null);
        }
        catch (InvalidKeyException e)
        {
            // ignore okay
        }
        catch (InvalidAlgorithmParameterException e)
        {
            // ignore okay
        }
        
        try
        {
            mac.init(null);
        }
        catch (InvalidKeyException e)
        {
            // ignore okay
        }
    }
    
    public void performTest()
        throws Exception
    {
        testHMac("HMac-SHA1", output1);
        testHMac("HMac-MD5", output2);
        testHMac("HMac-SHA224", output224);
        testHMac("HMac-SHA256", output256);
        testHMac("HMac-SHA384", output384);
        testHMac("HMac-SHA512", output512);

        // test for compatibility with broken HMac.
        testHMac("OldHMacSHA384", outputOld384);
        testHMac("OldHMacSHA512", outputOld512);

        testExceptions();
    }

    public String getName()
    {
        return "HMac";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new HMacTest());
    }
}
