package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import java.math.BigInteger;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.Date;

/**
 * This class is an <code>Selector</code> like implementation to select
 * attribute certificates from a given set of criteria.
 *
 * @see org.bouncycastle.x509.X509AttributeCertificate
 * @see org.bouncycastle.x509.X509Store
 */
public class X509AttributeCertStoreSelector
    implements Selector
{

    // TODO: name constraints???

    private AttributeCertificateHolder holder;

    private AttributeCertificateIssuer issuer;

    private BigInteger serialNumber;

    private Date attributeCertificateValid;

    private X509AttributeCertificate attributeCert;

    public X509AttributeCertStoreSelector()
    {
        super();
    }

    /**
     * Decides if the given attribute certificate should be selected.
     *
     * @param obj The attribute certificate which should be checked.
     * @return <code>true</code> if the attribute certificate can be selected,
     *         <code>false</code> otherwise.
     */
    public boolean match(Object obj)
    {
        if (!(obj instanceof X509AttributeCertificate))
        {
            return false;
        }

        X509AttributeCertificate attrCert = (X509AttributeCertificate)obj;

        if (this.attributeCert != null)
        {
            if (!this.attributeCert.equals(attrCert))
            {
                return false;
            }
        }
        if (serialNumber != null)
        {
            if (!attrCert.getSerialNumber().equals(serialNumber))
            {
                return false;
            }
        }
        if (holder != null)
        {
            if (!attrCert.getHolder().equals(holder))
            {
                return false;
            }
        }
        if (issuer != null)
        {
            if (!attrCert.getIssuer().equals(issuer))
            {
                return false;
            }
        }

        if (attributeCertificateValid != null)
        {
            try
            {
                attrCert.checkValidity(attributeCertificateValid);
            }
            catch (CertificateExpiredException e)
            {
                return false;
            }
            catch (CertificateNotYetValidException e)
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns a clone of this object.
     *
     * @return the clone.
     */
    public Object clone()
    {
        X509AttributeCertStoreSelector sel = new X509AttributeCertStoreSelector();
        sel.attributeCert = attributeCert;
        sel.attributeCertificateValid = getAttributeCertificateValid();
        sel.holder = holder;
        sel.issuer = issuer;
        sel.serialNumber = serialNumber;
        return sel;
    }

    /**
     * Returns the attribute certificate which must be matched.
     *
     * @return Returns the attribute certificate.
     */
    public X509AttributeCertificate getAttributeCert()
    {
        return attributeCert;
    }

    /**
     * Set the attribute certificate to be matched.
     *
     * @param attributeCert The attribute certificate to set.
     */
    public void setAttributeCert(X509AttributeCertificate attributeCert)
    {
        this.attributeCert = attributeCert;
    }

    /**
     * Get the criteria for the validity.
     *
     * @return Returns the attributeCertificateValid.
     */
    public Date getAttributeCertificateValid()
    {
        if (attributeCertificateValid != null)
        {
            return new Date(attributeCertificateValid.getTime());
        }

        return null;
    }

    /**
     * Set the time, when the certificate must be valid.
     *
     * @param attributeCertificateValid The attribute certificate validation time to set.
     */
    public void setAttributeCertificateValid(Date attributeCertificateValid)
    {
        if (attributeCertificateValid != null)
        {
            this.attributeCertificateValid = new Date(attributeCertificateValid.getTime());
        }
        else
        {
            this.attributeCertificateValid = null;
        }
    }

    /**
     * @return Returns the holder.
     */
    public AttributeCertificateHolder getHolder()
    {
        return holder;
    }

    /**
     * @param holder The holder to set.
     */
    public void setHolder(AttributeCertificateHolder holder)
    {
        this.holder = holder;
    }

    /**
     * @return Returns the issuer.
     */
    public AttributeCertificateIssuer getIssuer()
    {
        return issuer;
    }

    /**
     * @param issuer The issuer to set.
     */
    public void setIssuer(AttributeCertificateIssuer issuer)
    {
        this.issuer = issuer;
    }

    /**
     * @return Returns the serialNumber.
     */
    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * @param serialNumber The serialNumber to set.
     */
    public void setSerialNumber(BigInteger serialNumber)
    {
        this.serialNumber = serialNumber;
    }
}
