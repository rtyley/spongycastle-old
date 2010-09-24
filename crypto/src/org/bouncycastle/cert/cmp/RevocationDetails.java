package org.bouncycastle.cert.cmp;

import java.math.BigInteger;

import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.x509.X509Name;

public class RevocationDetails
{
    private RevDetails revDetails;

    public RevocationDetails(RevDetails revDetails)
    {
        this.revDetails = revDetails;
    }

    public X509Name getSubject()
    {
        return revDetails.getCertDetails().getSubject();
    }

    public X509Name getIssuer()
    {
        return revDetails.getCertDetails().getIssuer();
    }

    public BigInteger getSerialNumber()
    {
        return revDetails.getCertDetails().getSerialNumber().getValue();
    }

    public RevDetails toASN1Structure()
    {
        return revDetails;
    }
}
