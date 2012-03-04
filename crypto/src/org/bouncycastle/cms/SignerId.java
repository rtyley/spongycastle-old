package org.bouncycastle.cms;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CertSelector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;

/**
 * a basic index for a signer.
 */
public class SignerId
    extends X509CertSelector
    implements Selector
{
    private byte[] subjectKeyId;

    private X500Name issuer;
    private BigInteger serialNumber;

    /**
     * @deprecated use specific constructor.
     */
    public SignerId()
    {

    }

    /**
     * Construct a signer ID with the value of a public key's subjectKeyId.
     *
     * @param subjectKeyId a subjectKeyId
     */
    public SignerId(byte[] subjectKeyId)
    {
        setSubjectKeyID(subjectKeyId);
    }

    private void setSubjectKeyID(byte[] subjectKeyId)
    {
        try
        {
            super.setSubjectKeyIdentifier(new DEROctetString(subjectKeyId).getEncoded(ASN1Encoding.DER));
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("unable to encode subjectKeyId: " + e.getMessage());
        }

        this.subjectKeyId = subjectKeyId;
    }

    /**
     * Construct a signer ID based on the issuer and serial number of the signer's associated
     * certificate.
     *
     * @param issuer the issuer of the signer's associated certificate.
     * @param serialNumber the serial number of the signer's associated certificate.
     */
    public SignerId(X500Name issuer, BigInteger serialNumber)
    {
        setIssuerAndSerial(issuer, serialNumber);
    }

    private void setIssuerAndSerial(X500Name issuer, BigInteger serialNumber)
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
     * Construct a signer ID based on the issuer and serial number of the signer's associated
     * certificate.
     *
     * @param issuer the issuer of the signer's associated certificate.
     * @param serialNumber the serial number of the signer's associated certificate.
     * @param subjectKeyId the subject key identifier to use to match the signers associated certificate.
     */
    public SignerId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
    {
        setIssuerAndSerial(issuer, serialNumber);
        setSubjectKeyID(subjectKeyId);
    }

        // TODO: change to getIssuer() when dependency on X509CertSelector removed.
    X500Name getIssuerName()
    {
        return issuer;
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
        if (!(o instanceof SignerId))
        {
            return false;
        }

        SignerId id = (SignerId)o;

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
                    && iAndS.getSerialNumber().getValue().equals(this.serialNumber);
            }
            else if (this.getSubjectKeyIdentifier() != null)
            {
                Extension ext = certHldr.getExtension(Extension.subjectKeyIdentifier);

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
        else if (obj instanceof SignerInformation)
        {
            return ((SignerInformation)obj).getSID().equals(this);
        }

        return false;
    }
}
