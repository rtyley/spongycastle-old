package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESWrapEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * Test vectors from the NIST standard tests and Brian Gladman's vector set
 * <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">
 * http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
 */
public class AESTest
    extends CipherTest
{
    static Test[]  tests = 
            {
                new BlockCipherVectorTest(0, new AESEngine(),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
                new BlockCipherVectorTest(1, new AESEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000080")),
                        "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
                new BlockCipherMonteCarloTest(2, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
                new BlockCipherMonteCarloTest(3, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
                new BlockCipherVectorTest(4, new AESEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
                new BlockCipherMonteCarloTest(5, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
                new BlockCipherVectorTest(6, new AESEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
                new BlockCipherMonteCarloTest(7, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
                new BlockCipherVectorTest(8, new AESEngine(),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
                new BlockCipherVectorTest(9, new AESEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000080")),
                        "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
                new BlockCipherMonteCarloTest(10, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
                new BlockCipherMonteCarloTest(11, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
                new BlockCipherVectorTest(12, new AESEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
                new BlockCipherMonteCarloTest(13, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
                new BlockCipherVectorTest(14, new AESEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
                new BlockCipherMonteCarloTest(15, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168"),
                new BlockCipherVectorTest(16, new AESEngine(),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
                new BlockCipherVectorTest(17, new AESEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000080")),
                        "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
                new BlockCipherMonteCarloTest(18, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
                new BlockCipherMonteCarloTest(19, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
                new BlockCipherVectorTest(20, new AESEngine(),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
                new BlockCipherMonteCarloTest(21, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
                new BlockCipherVectorTest(22, new AESEngine(),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
                new BlockCipherMonteCarloTest(23, 10000, new AESEngine(),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168")
            };

    AESTest()
    {
        super(tests);
    }

    public String getName()
    {
        return "AES";
    }

    private TestResult wrapTest(
        int     id,
        byte[]  kek,
        byte[]  in,
        byte[]  out)
    {
        Wrapper wrapper = new AESWrapEngine();

        wrapper.init(true, new KeyParameter(kek));

        try
        {
            byte[]  cText = wrapper.wrap(in, 0, in.length);
            if (!Arrays.areEqual(cText, out))
            {
                return new SimpleTestResult(false, getName() + ": failed wrap test " + id  + " expected " + new String(Hex.encode(out)) + " got " + new String(Hex.encode(cText)));
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": failed wrap test exception " + e.toString());
        }

        wrapper.init(false, new KeyParameter(kek));

        try
        {
            byte[]  pText = wrapper.unwrap(out, 0, out.length);
            if (!Arrays.areEqual(pText, in))
            {
                return new SimpleTestResult(false, getName() + ": failed unwrap test " + id  + " expected " + new String(Hex.encode(in)) + " got " + new String(Hex.encode(pText)));
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": failed unwrap test exception.", e);
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public TestResult perform()
    {
        TestResult      result = super.perform();
        if (!result.isSuccessful())
        {
            return result;
        }

        byte[]  kek1 = Hex.decode("000102030405060708090a0b0c0d0e0f");
        byte[]  in1 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out1 = Hex.decode("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
        result = wrapTest(1, kek1, in1, out1);
        if (!result.isSuccessful())
        {
            return result;
        }

        byte[]  kek2 = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");
        byte[]  in2 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out2 = Hex.decode("96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d");
        result = wrapTest(2, kek2, in2, out2);
        if (!result.isSuccessful())
        {
            return result;
        }

        byte[]  kek3 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[]  in3 = Hex.decode("00112233445566778899aabbccddeeff");
        byte[]  out3 = Hex.decode("64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7");
        result = wrapTest(3, kek3, in3, out3);
        if (!result.isSuccessful())
        {
            return result;
        }

        byte[]  kek4 = Hex.decode("000102030405060708090a0b0c0d0e0f1011121314151617");
        byte[]  in4 = Hex.decode("00112233445566778899aabbccddeeff0001020304050607");
        byte[]  out4 = Hex.decode("031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2");
        result = wrapTest(4, kek4, in4, out4);
        if (!result.isSuccessful())
        {
            return result;
        }

        byte[]  kek5 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[]  in5 = Hex.decode("00112233445566778899aabbccddeeff0001020304050607");
        byte[]  out5 = Hex.decode("a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1");
        result = wrapTest(5, kek5, in5, out5);
        if (!result.isSuccessful())
        {
            return result;
        }

        byte[]  kek6 = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[]  in6 = Hex.decode("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        byte[]  out6 = Hex.decode("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");
        result = wrapTest(6, kek6, in6, out6);
        if (!result.isSuccessful())
        {
            return result;
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        AESTest         test = new AESTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
