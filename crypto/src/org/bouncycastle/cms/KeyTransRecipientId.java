package org.bouncycastle.cms;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;

public class KeyTransRecipientId
    extends RecipientId
{
    private byte[] subjectKeyId;

    private X500Name issuer;
    private BigInteger serialNumber;

    /**
     * Construct a key trans recipient ID with the value of a public key's subjectKeyId.
     *
     * @param subjectKeyId a subjectKeyId
     */
    public KeyTransRecipientId(byte[] subjectKeyId)
    {
        super(keyTrans);

        setSubjectKeyId(subjectKeyId);
    }

    private void setSubjectKeyId(byte[] subjectKeyId)
    {
        if (subjectKeyId != null)
        {
            try
            {
                super.setSubjectKeyIdentifier(new DEROctetString(subjectKeyId).getEncoded(ASN1Encoding.DER));
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException("unable to encode subjectKeyId: " + e.getMessage());
            }
        }

        this.subjectKeyId = subjectKeyId;
    }

    /**
     * Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated
     * certificate.
     *
     * @param issuer the issuer of the recipient's associated certificate.
     * @param serialNumber the serial number of the recipient's associated certificate.
     */
    public KeyTransRecipientId(X500Name issuer, BigInteger serialNumber)
    {
        super(keyTrans);

        setIssuerSerial(issuer, serialNumber);
    }

    private void setIssuerSerial(X500Name issuer, BigInteger serialNumber)
    {
        this.issuer = issuer;
        this.serialNumber = serialNumber;

        try
        {
            this.setIssuer(issuer.getEncoded(ASN1Encoding.DER));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid issuer: " + e.getMessage());
        }
        this.setSerialNumber(serialNumber);
    }

    /**
     * Construct a key trans recipient ID based on the issuer and serial number of the recipient's associated
     * certificate.
     *
     * @param issuer the issuer of the recipient's associated certificate.
     * @param serialNumber the serial number of the recipient's associated certificate.
     * @param subjectKeyId the subject key identifier to use to match the recipients associated certificate.
     */
    public KeyTransRecipientId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
    {
        super(keyTrans);

        setIssuerSerial(issuer, serialNumber);
        setSubjectKeyId(subjectKeyId);
    }

    // TODO: change to getIssuer() when dependency on X509CertSelector removed.
    X500Name getIssuerName()
    {
        return issuer;
    }

    // TODO: change to getSubjectKeyIdentifier() when dependency on X509CertSelector removed.
    byte[] getSubjectKeyId()
    {
        return Arrays.clone(subjectKeyId);
    }

    public int hashCode()
    {
        int code = Arrays.hashCode(subjectKeyId);

        if (this.serialNumber != null)
        {
            code ^= this.serialNumber.hashCode();
        }

        if (this.issuer != null)
        {
            code ^= this.issuer.hashCode();
        }

        return code;
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof KeyTransRecipientId))
        {
            return false;
        }

        KeyTransRecipientId id = (KeyTransRecipientId)o;

        return Arrays.areEqual(subjectKeyId, id.subjectKeyId)
            && equalsObj(this.serialNumber, id.serialNumber)
            && equalsObj(this.issuer, id.issuer);
    }

    private boolean equalsObj(Object a, Object b)
    {
        return (a != null) ? a.equals(b) : b == null;
    }

    public boolean match(Object obj)
    {
        if (obj instanceof X509CertificateHolder)
        {
            X509CertificateHolder certHldr = (X509CertificateHolder)obj;

            if (this.getSerialNumber() != null)
            {
                IssuerAndSerialNumber iAndS = new IssuerAndSerialNumber(certHldr.toASN1Structure());

                return iAndS.getName().equals(this.issuer)
                    && iAndS.getSerialNumber().getValue().equals(this.getSerialNumber());
            }
            if (this.getSubjectKeyIdentifier() != null)
            {
                X509Extension ext = certHldr.getExtension(X509Extension.subjectKeyIdentifier);

                if (ext == null)
                {
                    return Arrays.areEqual(subjectKeyId, MSOutlookKeyIdCalculator.calculateKeyId(certHldr.getSubjectPublicKeyInfo()));
                }

                byte[] subKeyID = ASN1OctetString.getInstance(ext.getParsedValue()).getOctets();

                return Arrays.areEqual(subjectKeyId, subKeyID);
            }
        }
        else if (obj instanceof byte[])
        {
            return Arrays.areEqual(subjectKeyId, (byte[])obj);
        }
        else if (obj instanceof KeyTransRecipientInformation)
        {
            return ((KeyTransRecipientInformation)obj).getRID().equals(this);
        }

        return false;
    }
}
