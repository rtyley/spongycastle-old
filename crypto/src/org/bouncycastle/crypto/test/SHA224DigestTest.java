package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * standard vector test for SHA-224 from RFC 3874 - only the last three are in
 * the RFC.
 */
public class SHA224DigestTest
    implements Test
{
    static private String  testVec1 = "";
    static private String  resVec1 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";

    static private String  testVec2 = "61";
    static private String  resVec2 = "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5";

    static private String  testVec3 = "616263";
    static private String  resVec3 = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";

    static private String  testVec4 = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
    static private String  resVec4 = "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525";

    // 1 million 'a'
    static private String  testVec5 = "61616161616161616161";
    static private String  resVec5 = "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67";

    public String getName()
    {
        return "SHA224";
    }

    public TestResult perform()
    {
        Digest  digest = new SHA224Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];
        String  resStr;

        //
        // test 1
        //
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec1.equals(resStr))
        {
            return new SimpleTestResult(false,
                "SHA-256 failing standard vector test 1"
                + System.getProperty("line.separator")
                + "    expected: " + resVec1
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 2
        //
        byte[]  bytes = Hex.decode(testVec2);

        digest.update(bytes, 0, bytes.length);

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec2.equals(resStr))
        {
            return new SimpleTestResult(false,
                "SHA-256 failing standard vector test 2"
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
                "SHA-256 failing standard vector test 3"
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
                "SHA-256 failing standard vector test 4"
                + System.getProperty("line.separator")
                + "    expected: " + resVec4
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        //
        // test 5
        //
        bytes = Hex.decode(testVec4);

        digest.update(bytes, 0, bytes.length/2);

        // clone the Digest
        Digest d = new SHA224Digest((SHA224Digest)digest);

        digest.update(bytes, bytes.length/2, bytes.length - bytes.length/2);
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "SHA224 failing standard vector test 5"
                + System.getProperty("line.separator")
                + "    expected: " + resVec4
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        d.update(bytes, bytes.length/2, bytes.length - bytes.length/2);
        d.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "SHA224 failing standard vector test 5"
                + System.getProperty("line.separator")
                + "    expected: " + resVec4
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        // test 6
        bytes = Hex.decode(testVec5);
        for ( int i = 0; i < 100000; i++ )
        {
            digest.update(bytes, 0, bytes.length);
        }
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec5.equals(resStr))
        {
            return new SimpleTestResult(false,
                "SHA-256 failing standard vector test 5"
                + System.getProperty("line.separator")
                + "    expected: " + resVec5
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        SHA224DigestTest  test = new SHA224DigestTest();
        TestResult        result = test.perform();

        System.out.println(result);
    }
}
