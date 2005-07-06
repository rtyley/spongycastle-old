package org.bouncycastle.cms;

import org.bouncycastle.jce.cert.X509CertSelector;

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
                code ^= (keyIdentifier[i] << (i % 4));
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

        if (id.keyIdentifier != null)
        {
            if (keyIdentifier == null)
            {
                return false;
            }
            
            if (keyIdentifier.length != id.keyIdentifier.length)
            {
                return false;
            }

            for (int i = 0; i != keyIdentifier.length; i++)
            {
                if (keyIdentifier[i] != id.keyIdentifier[i])
                {
                    return false;
                }
            }
        }

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

        return true;
    }
}
