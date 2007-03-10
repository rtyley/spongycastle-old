package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.isismtt.x509.Restriction;
import org.bouncycastle.asn1.x500.DirectoryString;

import java.io.IOException;

public class RestrictionUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "Restriction";
    }

    public void performTest()
        throws Exception
    {
        DirectoryString res = new DirectoryString("test");
        Restriction restriction = new Restriction(res.getString());

        checkConstruction(restriction, res);

        restriction = Restriction.getInstance(null);

        if (restriction != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            Restriction.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        Restriction restriction,
        DirectoryString res)
        throws IOException
    {
        checkValues(restriction, res);

        restriction = Restriction.getInstance(restriction);

        checkValues(restriction, res);

        ASN1InputStream aIn = new ASN1InputStream(restriction.toASN1Object().getEncoded());

        DERString str = (DERString)aIn.readObject();

        restriction = Restriction.getInstance(str);

        checkValues(restriction, res);
    }

    private void checkValues(
        Restriction restriction,
        DirectoryString res)
    {
        checkMandatoryField("restriction", res, restriction.getRestriction());
    }

    public static void main(
        String[]    args)
    {
        runTest(new RestrictionUnitTest());
    }
}
