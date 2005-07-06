package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * standard vector test for SHA-256 from FIPS Draft 180-2.
 *
 * Note, the first two vectors are _not_ from the draft, the last three are.
 */
public class SHA256DigestTest
    implements Test
{
    static private String  testVec1 = "";
    static private String  resVec1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    static private String  testVec2 = "61";
    static private String  resVec2 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";

    static private String  testVec3 = "616263";
    static private String  resVec3 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    static private String  testVec4 = "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071";
    static private String  resVec4 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    // 1 million 'a'
    static private String  testVec5 = "61616161616161616161";
    static private String  resVec5 = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    public String getName()
    {
        return "SHA256";
    }

    public TestResult perform()
    {
        Digest  digest = new SHA256Digest();
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
        Digest d = new SHA256Digest((SHA256Digest)digest);

        digest.update(bytes, bytes.length/2, bytes.length - bytes.length/2);
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "SHA256 failing standard vector test 5"
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
                "SHA256 failing standard vector test 5"
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
        SHA256DigestTest  test = new SHA256DigestTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
