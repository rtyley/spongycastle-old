package org.bouncycastle.ocsp;

import java.text.ParsePosition;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.x509.CRLReason;

/**
 * wrapper for the RevokedInfo object
 */
public class RevokedStatus
    implements CertificateStatus
{
    RevokedInfo info;

    public RevokedStatus(
        RevokedInfo info)
    {
        this.info = info;
    }
    
    public RevokedStatus(
        Date        revocationDate,
        int         reason)
    {
        this.info = new RevokedInfo(new DERGeneralizedTime(revocationDate), new CRLReason(reason));
    }

    public Date getRevocationTime()
    {
        SimpleDateFormat dateF = new SimpleDateFormat("yyyyMMddHHmmssz");

        return dateF.parse(info.getRevocationTime().getTime(), new ParsePosition(0));
    }

    public boolean hasRevocationReason()
    {
        return (info.getRevocationReason() != null);
    }

    /**
     * return the revocation reason. Note: this field is optional, test for it
     * with hasRevocationReason() first.
     * @exception IllegalStateException if a reason is asked for and none is avaliable
     */
    public int getRevocationReason()
    {
        if (info.getRevocationReason() == null)
        {
            throw new IllegalStateException("attempt to get a reason where none is available");
        }

        return info.getRevocationReason().getValue().intValue();
    }
}
