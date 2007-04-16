package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * HC-128 and HC-256 Tests. Based on the test vectors in the official reference
 * papers, respectively:
 * 
 * http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
 * http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc256_p3.pdf
 */
public class HCFamilyTest
    extends SimpleTest
{
    private static final byte[] MSG = new byte[64];

    private static final byte[] K256A = new byte[32];
    private static final byte[] K256B = Hex
        .decode("55000000000000000000000000000000"
            + "00000000000000000000000000000000");

    private static final byte[] IVA = new byte[32];
    private static final byte[] IVB = new byte[]{0x1};

    private static final byte[] HC256A = Hex
        .decode("8589075b0df3f6d82fc0c5425179b6a6"
            + "3465f053f2891f808b24744e18480b72"
            + "ec2792cdbf4dcfeb7769bf8dfa14aee4"
            + "7b4c50e8eaf3a9c8f506016c81697e32");
    private static final byte[] HC256B = Hex
        .decode("bfa2e2afe9ce174f8b05c2feb18bb1d1"
            + "ee42c05f01312b71c61f50dd502a080b"
            + "edfec706633d9241a6dac448af8561ff"
            + "5e04135a9448c4342de7e9f337520bdf");
    private static final byte[] HC256C = Hex
        .decode("fe4a401ced5fe24fd19a8f956fc036ae"
            + "3c5aa68823e2abc02f90b3aea8d30e42"
            + "59f03a6c6e39eb448f7579fb70137a5e"
            + "6d10b7d8add0f7cd723423daf575dde6");
    private static final byte[] HC256D = Hex
        .decode("c6b6fb99f2ae1440a7d4ca342011694e"
            + "6f36b4be420db05d4745fd907c630695"
            + "5f1d7bda13ae7e36aebc5399733b7f37"
            + "95f34066b601d21f2d8cf830a9c08937");

    private static final byte[] K128A = new byte[16];
    private static final byte[] K128B = Hex
        .decode("55000000000000000000000000000000");

    private static final byte[] HC128A = Hex
        .decode("731500823bfd03a0fb2fd77faa63af0e"
            + "de122fc6a7dc29b662a685278b75ec68"
            + "9036db1e8189600500ade078491fbf9a"
            + "1cdc30136c3d6e2490f664b29cd57102");
    private static final byte[] HC128B = Hex
        .decode("c01893d5b7dbe9588f65ec9864176604"
            + "36fc6724c82c6eec1b1c38a7c9b42a95"
            + "323ef1230a6a908bce757b689f14f7bb"
            + "e4cde011aeb5173f89608c94b5cf46ca");
    private static final byte[] HC128C = Hex
        .decode("518251a404b4930ab02af9310639f032"
            + "bcb4a47a5722480b2bf99f72cdc0e566"
            + "310f0c56d3cc83e8663db8ef62dfe07f"
            + "593e1790c5ceaa9cab03806fc9a6e5a0");
    private static final byte[] HC128D = Hex
        .decode("a4eac0267e4911266a2a384f5c4e1329"
            + "da407fa155e6b1ae05c6fdf3bbdc8a86"
            + "7a699aa01a4dc11763658cccd3e62474"
            + "9cf8236f0131be21c3a51de9d12290de");

    public String getName()
    {
        return "HC-128 and HC-256";
    }

    public void performTest()
    {
        StreamCipher hc = new HC256Engine();
        HCTest(hc, "HC-256 - A", K256A, IVA, HC256A);
        HCTest(hc, "HC-256 - B", K256A, IVB, HC256B);
        HCTest(hc, "HC-256 - C", K256B, IVA, HC256C);
        HCTest2(hc, "HC-256 - D", K256A, IVA, HC256D, 0x10000);

        hc = new HC128Engine();
        HCTest(hc, "HC-128 - A", K128A, IVA, HC128A);
        HCTest(hc, "HC-128 - B", K128A, IVB, HC128B);
        HCTest(hc, "HC-128 - C", K128B, IVA, HC128C);
        HCTest2(hc, "HC-128 - D", K128A, IVA, HC128D, 0x100000);
    }

    private void HCTest(StreamCipher hc, String test, byte[] key, byte[] IV, byte[] expected)
    {
        KeyParameter kp = new KeyParameter(key);
        ParametersWithIV ivp = new ParametersWithIV(kp, IV);
        hc.init(true, ivp);
        for (int i = 0; i < 64; i++)
        {
            if (hc.returnByte(MSG[i]) != expected[i])
            {
                fail(test + " failure");
            }
        }
    }

    private void HCTest2(StreamCipher hc, String test, byte[] key, byte[] IV, byte[] expected,
                         int times)
    {
        KeyParameter kp = new KeyParameter(key);
        ParametersWithIV ivp = new ParametersWithIV(kp, IV);
        hc.init(true, ivp);
        byte[] result = new byte[64];
        for (int j = 0; j < times; j++)
        {
            for (int i = 0; i < 64; i++)
            {
                result[i] = hc.returnByte(result[i]);
            }
        }

        for (int i = 0; i < 64; i++)
        {
            if (result[i] != expected[i])
            {
                fail(test + " failure at byte " + i);
            }
        }
    }

    public static void main(String[] args)
    {
        runTest(new HCFamilyTest());
    }
}
