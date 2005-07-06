package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * standard vector test for MD2
 * from RFC1319 by B.Kaliski of RSA Laboratories April 1992
 *
 */
public class MD2DigestTest
    implements Test
{
    static private String  testVec1 = "";
    static private String  resVec1 = "8350e5a3e24c153df2275c9f80692773";
    static private String  testVec2 = "61";
    static private String  resVec2 = "32ec01ec4a6dac72c0ab96fb34c0b5d1";
    static private String  testVec3 = "616263";
    static private String  resVec3 = "da853b0d3f88d99b30283a69e6ded6bb";
    static private String  testVec4 = "6d65737361676520646967657374";
    static private String  resVec4 = "ab4f496bfb2a530b219ff33031fe06b0";
    static private String  testVec5 = "6162636465666768696a6b6c6d6e6f707172737475767778797a";
    static private String  resVec5 = "4e8ddff3650292ab5a4108c3aa47940b";
    static private String  testVec6 = "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839";
    static private String  resVec6 = "da33def2a42df13975352846c30338cd";
    static private String  testVec7 = "3132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334353637383930";
    static private String  resVec7 = "d5976f79d83d3a0dc9806c3c66f3efd8";

    public String getName()
    {
        return "MD2";
    }

    public TestResult perform()
    {
        Digest  digest = new MD2Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];
        String  resStr;

        //
        // test 1
        //
        byte[]  bytes = Hex.decode(testVec1);
        digest.update(bytes, 0, bytes.length);
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec1.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD2 failing standard vector test 1"
                + System.getProperty("line.separator")
                + "    expected: " + resVec1
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 2
        //
        bytes = Hex.decode(testVec2);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec2.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD2 failing standard vector test 2"
                + System.getProperty("line.separator")
                + "    expected: " + resVec2
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 3
        //
        bytes = Hex.decode(testVec3);
        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec3.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD2 failing standard vector test 3"
                + System.getProperty("line.separator")
                + "    expected: " + resVec3
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 4
        //

        bytes = Hex.decode(testVec4);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD2 failing standard vector test 4"
                + System.getProperty("line.separator")
                + "    expected: " + resVec4
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }
        //
        // test 5
        //
        bytes = Hex.decode(testVec5);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec5.equals(resStr))
        {
            return new SimpleTestResult(false,
          //System.err.println(
                "MD2 failing standard vector test 5"
                + System.getProperty("line.separator")
                + "    expected: " + resVec5
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }
        //
        // test 6
        //
        bytes = Hex.decode(testVec6);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec6.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD2 failing standard vector test 6"
                + System.getProperty("line.separator")
                + "    expected: " + resVec6
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }
        //
        // test 7
        //
        bytes = Hex.decode(testVec7);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec7.equals(resStr))
        {
            return new SimpleTestResult(false,
                "MD2 failing standard vector test 7"
                + System.getProperty("line.separator")
                + "    expected: " + resVec7
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        MD2DigestTest   test = new MD2DigestTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
