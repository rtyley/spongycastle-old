package org.bouncycastle.cms;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CertSelector;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Selector;

public class RecipientId
    extends X509CertSelector
    implements Selector
{
    byte[]  keyIdentifier = null;

    /**
     * set a secret key identifier (for use with KEKRecipientInfo)
     */
    public void setKeyIdentifier(
        byte[]  keyIdentifier)
    {
        this.keyIdentifier = keyIdentifier;
    }

    /**
     * return the secret key identifier
     */
    public byte[] getKeyIdentifier()
    {
        return keyIdentifier;
    }

    public int hashCode()
    {
        int code = Arrays.hashCode(keyIdentifier)
            ^ Arrays.hashCode(this.getSubjectKeyIdentifier());

        BigInteger serialNumber = this.getSerialNumber();
        if (serialNumber != null)
        {
            code ^= serialNumber.hashCode();
        }

        String issuer = this.getIssuerAsString();
        if (issuer != null)
        {
            code ^= issuer.hashCode();
        }

        return code;
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof RecipientId))
        {
            return false;
        }

        RecipientId id = (RecipientId)o;

        return Arrays.areEqual(keyIdentifier, id.keyIdentifier)
            && Arrays.areEqual(this.getSubjectKeyIdentifier(), id.getSubjectKeyIdentifier())
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
                byte[] extSubKeyID = this.getSubjectKeyIdentifier();

                X509Extension ext = certHldr.getExtension(X509Extension.subjectKeyIdentifier);

                if (ext == null)
                {
                    Digest dig = new SHA1Digest();
                    byte[] hash = new byte[dig.getDigestSize()];
                    byte[] spkiEnc = certHldr.getSubjectPublicKeyInfo().getDEREncoded();

                    // try the outlook 2010 calculation
                    dig.update(spkiEnc, 0, spkiEnc.length);

                    dig.doFinal(hash, 0);

                    return Arrays.areEqual(extSubKeyID, hash);
                }

                byte[] subKeyID = ASN1OctetString.getInstance(ext.getParsedValue()).getOctets();

                return Arrays.areEqual(extSubKeyID, subKeyID);
            }
        }
        else if (obj instanceof byte[])
        {
            return Arrays.areEqual(this.getKeyIdentifier(), (byte[])obj);
        }

        return false;
    }
}
