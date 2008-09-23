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

    private static final byte[] expected0SHA1 = Hex.decode("ab02c2e86df828f7da5020d56e0fc258a67c06a9");
    private static final byte[] noCycle0SHA1 = Hex.decode("d57ccd0eb12c3938d59226412bc1268037b6b846");
    private static final byte[] expected0SHA256 = Hex.decode("4224cd59d26b5033eeb5404cf4fb3b1c15306ca1608c1248725ce5a97070cb61");
    private static final byte[] noCycle0SHA256 = Hex.decode("e5776c4483486ba7be081f4e1b9dafbab25c8fae290fd5474c1ceda2c16f9509");
    private static final byte[] expected100SHA1 = Hex.decode("39e2ba34bc93cbfadd35c5e2380cbca235f45c6c");
    private static final byte[] expected100SHA256 = Hex.decode("81dcfafc885914057876e1a59be4322d89f1a2b55f5114570a595b4ae89aaf02");
    private static final byte[] expectedTestSHA1 = Hex.decode("ddb3c8f6747d991bbe492f35d3c2f776e7fbddce");
    private static final byte[] expectedTestSHA256 = Hex.decode("02322d6d60d552ae1948f05ac76cb82af0e0ab2ebcecc197e04118e4f946e54e");

    private static final byte[] sha1Xors = Hex.decode("084b8403297e0be0fc2eb5a9dc3d9edc095a21a0");
    private static final byte[] sha256Xors = Hex.decode("c260f14a3bc773e07239e5260f16b0c458227a2920227462f8a9bb8416ed943f");

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
                fail("or test failed for " + digest.getAlgorithmName());
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
