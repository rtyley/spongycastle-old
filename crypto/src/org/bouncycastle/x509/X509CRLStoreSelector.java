package org.bouncycastle.x509;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.util.Selector;

import java.io.IOException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;

/**
 * 
 * This class is a Selector implementation for X.509 certificate revocation
 * lists.
 * 
 * @see org.bouncycastle.util.Selector
 * @see org.bouncycastle.x509.X509Store
 * @see org.bouncycastle.jce.provider.X509StoreCRLCollection
 */
public class X509CRLStoreSelector extends X509CRLSelector implements Selector
{
    private boolean deltaCRLIndicator = false;

    public boolean match(Object obj)
    {
        if (!(obj instanceof X509CRL))
        {
            return false;
        }
        X509CRL crl = (X509CRL)obj;
        if (isDeltaCRLIndicatorEnabled())
        {
            byte[] dci = crl.getExtensionValue(X509Extensions.DeltaCRLIndicator.getId());
            if (dci == null)
            {
                return false;
            }
        }
        return super.match((X509CRL)obj);
    }

    /**
     * Returns if this selector must match CRLs with the delta CRL indicator
     * extension set.
     *
     * @return Returns <code>true</code> if only CRLs with the delta CRL
     *         indicator extension are selected.
     */
    public boolean isDeltaCRLIndicatorEnabled()
    {
        return deltaCRLIndicator;
    }

    /**
     * If this is set to <code>true</code> the CRL reported contains the delta
     * CRL indicator CRL extension.
     *
     * @param deltaCRLIndicator <code>true</code> if the delta CRL indicator extension must
     *                          be in the CRL.
     */
    public void setDeltaCRLIndicatorEnabled(boolean deltaCRLIndicator)
    {
        this.deltaCRLIndicator = deltaCRLIndicator;
	}

    /**
     * Returns an instance of this from a <code>X509CRLSelector</code>.
     *
     * @param selector A <code>X509CRLSelector</code> instance.
     * @return An instance of an <code>X509CRLStoreSelector</code>.
     * @exception IllegalArgumentException if selector is null or creation fails.
     */
    public static X509CRLStoreSelector getInstance(X509CRLSelector selector)
    {
        if (selector == null)
        {
            throw new IllegalArgumentException("cannot create from null selector");
        }
        X509CRLStoreSelector cs = new X509CRLStoreSelector();
        cs.setCertificateChecking(selector.getCertificateChecking());
        cs.setDateAndTime(selector.getDateAndTime());
        try
        {
            cs.setIssuerNames(selector.getIssuerNames());
        }
        catch (IOException e)
        {
            // cannot happen
            throw new IllegalArgumentException(e.getMessage());
        }
        cs.setIssuers(selector.getIssuers());
        cs.setMaxCRLNumber(selector.getMaxCRL());
        cs.setMinCRLNumber(selector.getMinCRL());
        return cs;
    }
}
