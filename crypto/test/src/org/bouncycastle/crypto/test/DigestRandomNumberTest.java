package org.bouncycastle.crypto.test;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.Digest;

public class DigestRandomNumberTest
    extends SimpleTest
{
    private static final byte[] ZERO_SEED = { 0, 0, 0, 0, 0, 0, 0, 0 };

    private static final byte[] TEST_SEED = Hex.decode("81dcfafc885914057876");

    private static final byte[] expected0SHA1 = Hex.decode("0abca114c08f091b7f8e4034e3b859adc80b2068");
    private static final byte[] noCycle0SHA1 = Hex.decode("d57ccd0eb12c3938d59226412bc1268037b6b846");
    private static final byte[] expected0SHA256 = Hex.decode("04d3a268c6b692bb30f3a07b348e5a196b8e43d3bc408774ad83dc6c84097d99");
    private static final byte[] noCycle0SHA256 = Hex.decode("e5776c4483486ba7be081f4e1b9dafbab25c8fae290fd5474c1ceda2c16f9509");
    private static final byte[] expected100SHA1 = Hex.decode("21d294a8b508308c9ec3fe12d3603d4b9bf86e60");
    private static final byte[] expected100SHA256 = Hex.decode("e859016781291393ee96f104a58318923764a506be69f1f6a98c549b5f7f7584");
    private static final byte[] expectedTestSHA1 = Hex.decode("f39ef23a6fa0a1c31a8c4a3ed8e92bf7b453f281");
    private static final byte[] expectedTestSHA256 = Hex.decode("8637edc3706c98d00590704f19efb1457391b8ede7f71d6d5b0c568a3be6637a");

    private static final byte[] sha1Xors = Hex.decode("5a45ec9dbbbc86bf18432510ebabc51152d61d24");
    private static final byte[] sha256Xors = Hex.decode("c706bfc07e262339fc3850633bbec344b46b18c8bf9460391829955df0e2f9c3");

    public String getName()
    {
        return "DigestRandomNumber";
    }

    private void doExpectedTest(Digest digest, int seed, byte[] expected)
    {
        doExpectedTest(digest, seed, expected, null);
    }
    
    private void doExpectedTest(Digest digest, int seed, byte[] expected, byte[] noCycle)
    {
        DigestRandomGenerator rGen = new DigestRandomGenerator(digest);
        byte[] output = new byte[digest.getDigestSize()];

        rGen.addSeedMaterial(seed);

        for (int i = 0; i != 1024; i++)
        {
             rGen.nextBytes(output);
        }

        if (noCycle != null)
        {
            if (Arrays.areEqual(noCycle, output))
            {
                fail("seed not being cycled!");
            }
        }

        if (!Arrays.areEqual(expected, output))
        {
            fail("expected output doesn't match");
        }
    }

    private void doExpectedTest(Digest digest, byte[] seed, byte[] expected)
    {
        DigestRandomGenerator rGen = new DigestRandomGenerator(digest);
        byte[] output = new byte[digest.getDigestSize()];

        rGen.addSeedMaterial(seed);

        for (int i = 0; i != 1024; i++)
        {
             rGen.nextBytes(output);
        }

        if (!Arrays.areEqual(expected, output))
        {
            fail("expected output doesn't match");
        }
    }

    private void doCountTest(Digest digest, byte[] seed, byte[] expectedXors)
    {
        DigestRandomGenerator rGen = new DigestRandomGenerator(digest);
        byte[] output = new byte[digest.getDigestSize()];
        int[] averages = new int[digest.getDigestSize()];
        byte[] ands = new byte[digest.getDigestSize()];
        byte[] xors = new byte[digest.getDigestSize()];
        byte[] ors = new byte[digest.getDigestSize()];

        rGen.addSeedMaterial(seed);

        for (int i = 0; i != 1000000; i++)
        {
             rGen.nextBytes(output);
             for (int j = 0; j != output.length; j++)
             {
                 averages[j] += output[j] & 0xff;
                 ands[j] &= output[j];
                 xors[j] ^= output[j];
                 ors[j] |= output[j];
             }
        }

        for (int i = 0; i != output.length; i++)
        {
            if ((averages[i] / 1000000) != 127)
            {
                fail("average test failed for " + digest.getAlgorithmName());
            }
            if (ands[i] != 0)
            {
                fail("and test failed for " + digest.getAlgorithmName());
            }
            if ((ors[i] & 0xff) != 0xff)
            {
                fail("or test failed for " + digest.getAlgorithmName());
            }
            if (xors[i] != expectedXors[i])
            {
                fail("xor test failed for " + digest.getAlgorithmName());
            }
        }
    }

    public void performTest()
        throws Exception
    {
        doExpectedTest(new SHA1Digest(), 0, expected0SHA1, noCycle0SHA1);
        doExpectedTest(new SHA256Digest(), 0, expected0SHA256, noCycle0SHA256);

        doExpectedTest(new SHA1Digest(), 100, expected100SHA1);
        doExpectedTest(new SHA256Digest(), 100, expected100SHA256);

        doExpectedTest(new SHA1Digest(), ZERO_SEED, expected0SHA1);
        doExpectedTest(new SHA256Digest(), ZERO_SEED, expected0SHA256);

        doExpectedTest(new SHA1Digest(), TEST_SEED, expectedTestSHA1);
        doExpectedTest(new SHA256Digest(), TEST_SEED, expectedTestSHA256);

        doCountTest(new SHA1Digest(), TEST_SEED, sha1Xors);
        doCountTest(new SHA256Digest(), TEST_SEED, sha256Xors);
    }

    public static void main(
        String[]    args)
    {
        runTest(new DigestRandomNumberTest());
    }
}
