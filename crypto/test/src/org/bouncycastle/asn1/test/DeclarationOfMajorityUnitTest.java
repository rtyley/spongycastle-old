package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.isismtt.x509.DeclarationOfMajority;

import java.io.IOException;
import java.util.Date;

public class DeclarationOfMajorityUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "DeclarationOfMajority";
    }

    public void performTest()
        throws Exception
    {
        DERGeneralizedTime dateOfBirth = new DERGeneralizedTime(new Date());
        DeclarationOfMajority decl = new DeclarationOfMajority(dateOfBirth);

        checkConstruction(decl, DeclarationOfMajority.dateOfBirth, dateOfBirth);

        decl = DeclarationOfMajority.getInstance(null);

        if (decl != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            DeclarationOfMajority.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        DeclarationOfMajority decl,
        int                   type,
        DERGeneralizedTime    dateOfBirth)
        throws IOException
    {
        checkValues(decl, type, dateOfBirth);

        decl = DeclarationOfMajority.getInstance(decl);

        checkValues(decl, type, dateOfBirth);

        ASN1InputStream aIn = new ASN1InputStream(decl.toASN1Object().getEncoded());

        DERTaggedObject info = (DERTaggedObject)aIn.readObject();

        decl = DeclarationOfMajority.getInstance(info);

        checkValues(decl, type, dateOfBirth);
    }

    private void checkValues(
        DeclarationOfMajority decl,
        int                   type,
        DERGeneralizedTime    dateOfBirth)
    {
        checkMandatoryField("type", type, decl.getType());
        checkOptionalField("dateOfBirth", dateOfBirth, decl.getDateOfBirth());
    }

    public static void main(
        String[]    args)
    {
        runTest(new DeclarationOfMajorityUnitTest());
    }
}
