package org.bouncycastle.cms.jcajce;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cms.KeyTransRecipientId;

public class JceKeyTransRecipientId
    extends KeyTransRecipientId
{
    /**
     * Construct a recipient identifier based on the issuer, serial number and subject key identifier (if present) of the passed in
     * certificate.
     *
     * @param certificate certificate providing the issue and serial number and subject key identifier.
     */
    public JceKeyTransRecipientId(X509Certificate certificate)
    {
        super(X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded()), certificate.getSerialNumber(), CMSUtils.getSubjectKeyId(certificate));
    }

    /**
     * Construct a recipient identifier based on the provided issuer and serial number..
     *
     * @param issuer the issuer to use.
     * @param serialNumber  the serial number to use.
     */
    public JceKeyTransRecipientId(X500Principal issuer, BigInteger serialNumber)
    {
        super(X500Name.getInstance(issuer.getEncoded()), serialNumber);
    }

    /**
     * Construct a recipient identifier based on the provided issuer, serial number, and subjectKeyId..
     *
     * @param issuer the issuer to use.
     * @param serialNumber  the serial number to use.
     * @param subjectKeyId the subject key ID to use.
     */
    public JceKeyTransRecipientId(X500Principal issuer, BigInteger serialNumber, byte[] subjectKeyId)
    {
        super(X500Name.getInstance(issuer.getEncoded()), serialNumber, subjectKeyId);
    }
}
