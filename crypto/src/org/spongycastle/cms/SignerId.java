package org.spongycastle.cms;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CertSelector;

import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.cms.IssuerAndSerialNumber;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.X509Extension;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.crypto.Digest;
import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.Selector;

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
        super.setSubjectKeyIdentifier(new DEROctetString(subjectKeyId).getDEREncoded());

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
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        try
        {
            this.setIssuer(issuer.getDEREncoded());
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid issuer: " + e.getMessage());
        }
        this.setSerialNumber(serialNumber);
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
                IssuerAndSerialNumber iAndS = certHldr.getIssuerAndSerialNumber();

                return iAndS.getName().equals(this.issuer)
                    && iAndS.getSerialNumber().getValue().equals(this.serialNumber);
            }
            else if (this.getSubjectKeyIdentifier() != null)
            {
                X509Extension ext = certHldr.getExtension(X509Extension.subjectKeyIdentifier);

                if (ext == null)
                {
                    Digest dig = new SHA1Digest();
                    byte[] hash = new byte[dig.getDigestSize()];
                    byte[] spkiEnc = certHldr.getSubjectPublicKeyInfo().getDEREncoded();

                    // try the outlook 2010 calculation
                    dig.update(spkiEnc, 0, spkiEnc.length);

                    dig.doFinal(hash, 0);

                    return Arrays.areEqual(subjectKeyId, hash);
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
