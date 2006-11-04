package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import java.security.cert.CRL;
import java.security.cert.X509CRLSelector;

public class X509CRLSelectorWrapper
    implements Selector
{
    private X509CRLSelector _selector;

    public X509CRLSelectorWrapper(X509CRLSelector selector)
    {
        _selector = selector;
    }

    public boolean match(Object obj)
    {
        return _selector.match((CRL)obj);
    }
}
