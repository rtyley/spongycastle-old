package org.bouncycastle.cert.crmf;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.generators.MGF1BytesGenerator;
import org.bouncycastle.crypto.params.MGFParameters;

public class FixedLengthMGF1Padder
    implements EncryptedValuePadder
{
    private int length;
    private SecureRandom random;
    private Digest dig = new SHA1Digest();

    public FixedLengthMGF1Padder(int length, SecureRandom random)
    {
        this.length = length;
        this.random = random;
    }

    public byte[] getPaddedData(byte[] data)
    {
        byte[] bytes = new byte[length];
        byte[] seed = new byte[dig.getDigestSize()];
        byte[] mask = new byte[length - dig.getDigestSize()];

        random.nextBytes(seed);

        MGF1BytesGenerator maskGen = new MGF1BytesGenerator(dig);

        maskGen.init(new MGFParameters(seed));

        maskGen.generateBytes(mask, 0, mask.length);

        System.arraycopy(seed, 0, bytes, 0, seed.length);
        System.arraycopy(data, 0, bytes, seed.length, data.length);

        for (int i = seed.length + data.length + 1; i != bytes.length; i++)
        {
            byte b = (byte)random.nextInt();

            bytes[i] = (b == 0) ? 1 : b;
        }
        
        for (int i = 0; i != mask.length; i++)
        {
            bytes[i + seed.length] ^= mask[i];
        }

        return bytes;
    }

    public byte[] getUnpaddedData(byte[] paddedData)
    {
        byte[] seed = new byte[dig.getDigestSize()];
        byte[] mask = new byte[length - dig.getDigestSize()];

        random.nextBytes(seed);

        System.arraycopy(paddedData, 0, seed, 0, seed.length);

        MGF1BytesGenerator maskGen = new MGF1BytesGenerator(dig);

        maskGen.init(new MGFParameters(seed));

        maskGen.generateBytes(mask, 0, mask.length);

        for (int i = 0; i != mask.length; i++)
        {
            paddedData[i + seed.length] ^= mask[i];
        }

        int end = 0;

        for (int i = paddedData.length - 1; i != seed.length; i--)
        {
            if (paddedData[i] == 0)
            {
                end = i;
                break;
            }
        }

        if (end == 0)
        {
            throw new IllegalStateException("bad padding in encoding");
        }

        byte[] data = new byte[end - seed.length];

        System.arraycopy(paddedData, seed.length, data, 0, data.length);

        return data;
    }
}
