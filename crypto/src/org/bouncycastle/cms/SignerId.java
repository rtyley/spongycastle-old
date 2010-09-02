package org.bouncycastle.cms;

import java.io.IOException;
import java.security.cert.X509CertSelector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
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
    public int hashCode()
    {
        int code = Arrays.hashCode(this.getSubjectKeyIdentifier());

        if (this.getSerialNumber() != null)
        {
            code ^= this.getSerialNumber().hashCode();
        }

        if (this.getIssuerAsString() != null)
        {
            code ^= this.getIssuerAsString().hashCode();
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

        return Arrays.areEqual(this.getSubjectKeyIdentifier(), id.getSubjectKeyIdentifier())
            && equalsObj(this.getSerialNumber(), id.getSerialNumber())
            && equalsObj(this.getIssuerAsString(), id.getIssuerAsString());
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

                try
                {
                    return iAndS.getName().equals(X509Name.getInstance(this.getIssuerAsBytes()))
                        && iAndS.getSerialNumber().getValue().equals(this.getSerialNumber());
                }
                catch (IOException e)
                {
                    return false;
                }
            }
            else if (this.getSubjectKeyIdentifier() != null)
            {
                X509Extension ext = certHldr.getExtension(new ASN1ObjectIdentifier(X509Extensions.SubjectKeyIdentifier.getId()));

                if (ext == null)
                {
                    return false;
                }

                byte[] subKeyID = ASN1OctetString.getInstance(ext.getValue()).getOctets();

                return Arrays.areEqual(this.getSubjectKeyIdentifier(), subKeyID);
            }
        }
        return false;  //To change body of implemented methods use File | Settings | File Templates.
    }
}
