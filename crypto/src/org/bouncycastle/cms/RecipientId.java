package org.bouncycastle.cms;

import java.security.cert.X509CertSelector;
import java.util.Arrays;

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
        int     code = 0;

        if (keyIdentifier != null)
        {
            for (int i = 0; i != keyIdentifier.length; i++)
            {
                code ^= ((keyIdentifier[i] & 0xff) << (i % 4));
            }
        }

        byte[]  subKeyId = this.getSubjectKeyIdentifier();

        if (subKeyId != null)
        {
            for (int i = 0; i != subKeyId.length; i++)
            {
                code ^= ((subKeyId[i] & 0xff) << (i % 4));
            }
        }

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
        if (!(o instanceof RecipientId))
        {
            return false;
        }

        RecipientId id = (RecipientId)o;

        return equalsByteArray(keyIdentifier, id.keyIdentifier)
            && equalsByteArray(this.getSubjectKeyIdentifier(), id.getSubjectKeyIdentifier())
            && equalsObj(this.getSerialNumber(), id.getSerialNumber())
            && equalsObj(this.getIssuerAsString(), id.getIssuerAsString());
    }

    private boolean equalsObj(Object a, Object b)
    {
        return (a != null) ? a.equals(b) : b == null;
    }

    private boolean equalsByteArray(byte[] a, byte[] b)
    {
        if (a != null)
        {
            return (b != null) && Arrays.equals(a, b);
        }

        return (b == null);
    }
}
