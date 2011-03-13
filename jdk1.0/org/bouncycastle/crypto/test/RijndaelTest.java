package org.spongycastle.crypto.test;

import org.spongycastle.crypto.engines.RijndaelEngine;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.util.test.Test;
import org.spongycastle.util.test.TestResult;

/**
 */
public class RijndaelTest
    extends CipherTest
{
    static Test[]  tests = 
            {
                new BlockCipherVectorTest(0, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("80000000000000000000000000000000")),
                        "00000000000000000000000000000000", "0EDD33D3C621E546455BD8BA1418BEC8"),
                new BlockCipherVectorTest(1, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("00000000000000000000000000000080")),
                        "00000000000000000000000000000000", "172AEAB3D507678ECAF455C12587ADB7"),
/*
                new BlockCipherMonteCarloTest(2, 10000, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "C34C052CC0DA8D73451AFE5F03BE297F"),
*/
                new BlockCipherMonteCarloTest(2, 100, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("00000000000000000000000000000000")),
                        "00000000000000000000000000000000", "73ec274b42decc2a923d973d31289803"),
/*
                new BlockCipherMonteCarloTest(3, 10000, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "ACC863637868E3E068D2FD6E3508454A"),
*/
                new BlockCipherMonteCarloTest(3, 100, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("5F060D3716B345C253F6749ABAC10917")),
                        "355F697E8B868B65B25A04E18D782AFA", "83b24df55c094168e7036527642b1dbe"),
                new BlockCipherVectorTest(4, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "6CD02513E8D4DC986B4AFE087A60BD0C"),
/*
                new BlockCipherMonteCarloTest(5, 10000, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "77BA00ED5412DFF27C8ED91F3C376172"),
*/
                new BlockCipherMonteCarloTest(5, 100, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("AAFE47EE82411A2BF3F6752AE8D7831138F041560631B114")),
                        "F3F6752AE8D7831138F041560631B114", "c8a8f465b898b2ebc1b86cbf1f366c09"),
                new BlockCipherVectorTest(6, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("0000000000000000000000000000000000000000000000000000000000000000")),
                        "80000000000000000000000000000000", "DDC6BF790C15760D8D9AEB6F9A75FD4E"),
/*
                new BlockCipherMonteCarloTest(7, 10000, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "E58B82BFBA53C0040DC610C642121168")
*/
                new BlockCipherMonteCarloTest(7, 100, new RijndaelEngine(128),
                        new KeyParameter(Hex.decode("28E79E2AFC5F7745FCCABE2F6257C2EF4C4EDFB37324814ED4137C288711A386")),
                        "C737317FE0846F132B23C8C2A672CE22", "8fa011e53ee83f5a63f568a01ace9f1e")
            };

    RijndaelTest()
    {
        super(tests);
    }

    public String getName()
    {
        return "Rijndael";
    }

    public static void main(
        String[]    args)
    {
        RijndaelTest    test = new RijndaelTest();
        TestResult      result = test.perform();

        System.out.println(result);
    }
}
