package org.bouncycastle.cms;

import java.security.cert.X509CertSelector;
import java.util.Arrays;

/**
 * a basic index for a signer.
 */
public class SignerId
    extends X509CertSelector
{
    public int hashCode()
    {
        int     code = 0;

        if (this.getSerialNumber() != null)
        {
            code ^= this.getSerialNumber().hashCode();
        }

        if (this.getIssuerAsString() != null)
        {
            code ^= this.getIssuerAsString().hashCode();
        }

        byte[] subjectId = this.getSubjectKeyIdentifier();
        if (subjectId != null)
        {
            for (int i = 0; i != subjectId.length; i++)
            {
                code ^= ((subjectId[i]) & 0xff) << (i % 4);
            }
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

        return equalsObj(this.getSerialNumber(), id.getSerialNumber())
            && equalsObj(this.getIssuerAsString(), id.getIssuerAsString())
            && equalsByteArray(this.getSubjectKeyIdentifier(), id.getSubjectKeyIdentifier());
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