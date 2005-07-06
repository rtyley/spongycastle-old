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

        if (id.getSerialNumber() != null)
        {
            if (!id.getSerialNumber().equals(this.getSerialNumber()))
            {
                return false;
            }
        }

        if (id.getIssuerAsString() != null)
        {
            if (!id.getIssuerAsString().equals(this.getIssuerAsString()))
            {
                return false;
            }
        }
        
        byte[] subjectId = this.getSubjectKeyIdentifier();
        if (subjectId != null)
        {
            byte[] otherId = id.getSubjectKeyIdentifier();
            
            if (otherId == null || !Arrays.equals(subjectId, otherId))
            {
                return false;
            }
        }

        return true;
    }
}