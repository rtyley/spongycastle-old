package org.bouncycastle.asn1.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.isismtt.ocsp.RequestedCertificate;

import java.io.IOException;

public class RequestedCertificateUnitTest
    extends ASN1UnitTest
{
    public String getName()
    {
        return "RequestedCertificate";
    }

    public void performTest()
        throws Exception
    {
        int type = 1;
        byte[] certOctets = new byte[20];

        RequestedCertificate requested = new RequestedCertificate(type, certOctets);

        checkConstruction(requested, type, certOctets);

        requested = RequestedCertificate.getInstance(null);

        if (requested != null)
        {
            fail("null getInstance() failed.");
        }

        try
        {
            RequestedCertificate.getInstance(new Object());

            fail("getInstance() failed to detect bad object.");
        }
        catch (IllegalArgumentException e)
        {
            // expected
        }
    }

    private void checkConstruction(
        RequestedCertificate requested,
        int type,
        byte[] certOctets)
        throws IOException
    {
        checkValues(requested, type, certOctets);

        requested = RequestedCertificate.getInstance(requested);

        checkValues(requested, type, certOctets);

        ASN1InputStream aIn = new ASN1InputStream(requested.toASN1Object().getEncoded());

        ASN1TaggedObject taggedObject = (ASN1TaggedObject)aIn.readObject();

        requested = RequestedCertificate.getInstance(taggedObject);

        checkValues(requested, type, certOctets);
    }

    private void checkValues(
        RequestedCertificate requested,
        int type,
        byte[] certOctets)
    {
        checkMandatoryField("certType", type, requested.getType());
        checkMandatoryField("certificateOctets", certOctets, requested.getCertifcateBytes());
    }

    public static void main(
        String[]    args)
    {
        runTest(new RequestedCertificateUnitTest());
    }
}
