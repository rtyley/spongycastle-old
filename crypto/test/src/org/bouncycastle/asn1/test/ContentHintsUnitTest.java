package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.ess.ContentHints;

import java.io.IOException;

public class ContentHintsUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "ContentHints";
    }

    public void performTest()
        throws Exception
    {
        DERUTF8String contentDescription = new DERUTF8String("Description");
        DERObjectIdentifier contentType = new DERObjectIdentifier("1.2.2.3");

        ContentHints hints = new ContentHints(contentType);

        checkConstruction(hints, contentType, null);

        hints = new ContentHints(contentType, contentDescription);

        checkConstruction(hints, contentType, contentDescription);

        hints = ContentHints.getInstance(null);

        if (hints != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            ContentHints.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        ContentHints hints,
        DERObjectIdentifier contentType,
        DERUTF8String description)
        throws IOException
    {
        checkValues(hints, contentType, description);

        hints = ContentHints.getInstance(hints);

        checkValues(hints, contentType, description);

        ASN1InputStream aIn = new ASN1InputStream(hints.toASN1Object().getEncoded());

        ASN1Sequence seq = (ASN1Sequence)aIn.readObject();

        hints = ContentHints.getInstance(seq);

        checkValues(hints, contentType, description);
    }

    private void checkValues(
        ContentHints hints,
        DERObjectIdentifier contentType,
        DERUTF8String description)
    {
        checkMandatoryField("contentType", contentType, hints.getContentType());
        checkOptionalField("description", description, hints.getContentDescription());
    }

    public static void main(
        String[]    args)
    {
        runTest(new ContentHintsUnitTest());
    }
}
