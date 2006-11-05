package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import org.bouncycastle.jce.cert.X509CRLSelector;
import java.security.cert.CRL;

public class X509CRLSelectorWrapper
    extends X509CRLSelector
    implements Selector
{
    public boolean match(Object obj)
    {
        if (!(obj instanceof CRL))
        {
            return false;
        }

        return this.match((CRL)obj);
    }
}
