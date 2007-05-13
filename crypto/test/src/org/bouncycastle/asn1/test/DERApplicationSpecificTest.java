package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

public class DERApplicationSpecificTest
    extends SimpleTest
{
    byte[] impData = Hex.decode("430109");

    public String getName()
    {
        return "DERApplicationSpecific";
    }

    public void performTest()
        throws Exception
    {
        DERInteger value = new DERInteger(9);

        DERApplicationSpecific tagged = new DERApplicationSpecific(false, 3, value);

        if (!areEqual(impData, tagged.getEncoded()))
        {
            fail("implicit encoding failed");
        }

        DERInteger recVal = (DERInteger)tagged.getObject(DERTags.INTEGER);

        if (!value.equals(recVal))
        {
            fail("implicit read back failed");
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new DERApplicationSpecificTest());
    }
}
