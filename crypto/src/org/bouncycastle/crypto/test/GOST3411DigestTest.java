package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class GOST3411DigestTest
    implements Test
{
    static private String  testVec1 = "";
    static private String  resVec1 =  "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"; //If S-box = D-A (see: digest/GOST3411Digest.java; function: E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-A");)
    //static private String  resVec1 =  "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"; //If S-box = D-Test (see: digest/GOST3411Digest.java; function:E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-Test");)

                                      //"This is message, length=32 bytes"
    static private String  testVec2 = "54686973206973206d6573736167652c206c656e6774683d3332206279746573";
    static private String  resVec2 =  "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb";  //If S-box = D-A (see: digest/GOST3411Digest.java; function: E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-A");)
    //static private String  resVec2 =  "b1c466d37519b82e8319819ff32595e047a28cb6f83eff1c6916a815a637fffa"; //If S-box = D-Test (see: digest/GOST3411Digest.java; function:E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-Test");)

                                      //"Suppose the original message has length = 50 bytes"
    static private String  testVec3 = "537570706f736520746865206f726967696e616c206d65737361676520686173206c656e677468203d203530206279746573";
    static private String  resVec3 =  "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011"; //If S-box = D-A (see: digest/GOST3411Digest.java; function: E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-A");)
    //static private String  resVec3 =  "471aba57a60a770d3a76130635c1fbea4ef14de51f78b4ae57dd893b62f55208"; //If S-box = D-Test (see: digest/GOST3411Digest.java; function:E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-Test");)

    static private String  testVec4 = "4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839";
    static private String  resVec4 =  "73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61"; //If S-box = D-A (see: digest/GOST3411Digest.java; function: E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-A");)
    //static private String  resVec4 =  "95c1af627c356496d80274330b2cff6a10c67b5f597087202f94d06d2338cf8e"; //If S-box = D-Test (see: digest/GOST3411Digest.java; function:E(byte[] in, byte[] key); string: CipherParameters  param = new GOST28147Parameters(key,"D-Test");)

    // 1 million 'a'
    static private String  testVec5 = "61616161616161616161";
    static private String  resVec5 = "8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f";

    public String getName()
    {
        return "GOST3411";
    }

    public TestResult perform()
    {
        Digest  digest = new GOST3411Digest();
        byte[]  resBuf = new byte[digest.getDigestSize()];
        String  resStr;

        //
        // test 1
        //
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec2.equals(resStr))

        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec1.equals(resStr))
        {
            return new SimpleTestResult(false,
                "GOST3411 failing standard vector test 1"
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
                "GOST3411 failing standard vector test 2"
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
                "GOST3411 failing standard vector test 3"
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
                "GOST3411 failing standard vector test 4"
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
        Digest d = new GOST3411Digest((GOST3411Digest)digest);

        digest.update(bytes, bytes.length/2, bytes.length - bytes.length/2);
        digest.doFinal(resBuf, 0);

        resStr = new String(Hex.encode(resBuf));
        if (!resVec4.equals(resStr))
        {
            return new SimpleTestResult(false,
                "GOST3411 failing standard vector test 5"
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
                "GOST3411 failing standard vector test 5"
                + System.getProperty("line.separator")
                + "    expected: " + resVec4
                + System.getProperty("line.separator")
                + "    got     : " + resStr);
        }

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
            "GOST3411 failing vector test 5"
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
        GOST3411DigestTest   test = new GOST3411DigestTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
