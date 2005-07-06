package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * standard vector test for SHA-512 from FIPS Draft 180-2.
 *
 * Note, the first two vectors are _not_ from the draft, the last three are.
 */
public class SHA512DigestTest
    implements Test
{
    static private String  testVec1 = "";
    static private String  resVec1 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    static private String  testVec2 = "61";
    static private String  resVec2 = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75";

    static private String  testVec3 = "616263";
    static private String  resVec3 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    static private String  testVec4 = "61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475";
    static private String  resVec4 = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";

    // 1 million 'a'
    static private String  testVec5 = "61616161616161616161";
    static private String  resVec5 = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";

    public String getName()
    {
        return "SHA512";
    }

    public TestResult perform()
    {
        Digest  digest = new SHA512Digest();
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
                "SHA-512 failing standard vector test 1"
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
                "SHA-512 failing standard vector test 2"
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
                "SHA-512 failing standard vector test 3"
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
                "SHA-512 failing standard vector test 4"
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
        Digest d = new SHA512Digest((SHA512Digest)digest);

        digest.update(bytes, bytes.length/2, bytes.length - bytes.length/2);
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "SHA512 failing standard vector test 5"
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
                "SHA512 failing standard vector test 5"
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
                "SHA-512 failing standard vector test 5"
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
        SHA512DigestTest  test = new SHA512DigestTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
