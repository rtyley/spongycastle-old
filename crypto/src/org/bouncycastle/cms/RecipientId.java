package org.bouncycastle.cms;

import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.security.cert.X509CertSelector;

public class RecipientId
    extends X509CertSelector
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
}
