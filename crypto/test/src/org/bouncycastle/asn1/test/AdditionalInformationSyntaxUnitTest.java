package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.isismtt.x509.AdditionalInformationSyntax;
import org.bouncycastle.asn1.x500.DirectoryString;

import java.io.IOException;

public class AdditionalInformationSyntaxUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "AdditionalInformationSyntax";
    }

    public void performTest()
        throws Exception
    {
        AdditionalInformationSyntax syntax = new AdditionalInformationSyntax("hello world");

        checkConstruction(syntax, new DirectoryString("hello world"));

        syntax = AdditionalInformationSyntax.getInstance(null);

        if (syntax != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            AdditionalInformationSyntax.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        AdditionalInformationSyntax syntax,
        DirectoryString information)
        throws IOException
    {
        checkValues(syntax, information);

        syntax = AdditionalInformationSyntax.getInstance(syntax);

        checkValues(syntax, information);

        ASN1InputStream aIn = new ASN1InputStream(syntax.toASN1Object().getEncoded());

        DERString info = (DERString)aIn.readObject();

        syntax = AdditionalInformationSyntax.getInstance(info);

        checkValues(syntax, information);
    }

    private void checkValues(
        AdditionalInformationSyntax syntax,
        DirectoryString information)
    {
        checkMandatoryField("information", information, syntax.getInformation());
    }

    public static void main(
        String[]    args)
    {
        runTest(new AdditionalInformationSyntaxUnitTest());
    }
}
