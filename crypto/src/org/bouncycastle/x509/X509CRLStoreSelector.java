package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import java.security.cert.CRL;
import java.security.cert.X509CRLSelector;

public class X509CRLStoreSelector
    extends X509CRLSelector
    implements Selector
{
    public boolean match(Object obj)
    {
        if (!(obj instanceof CRL))
        {
            return false;
        }
        return super.match((CRL)obj);
    }
}
