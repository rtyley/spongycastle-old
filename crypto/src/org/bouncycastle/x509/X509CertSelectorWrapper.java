package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;

public class X509CertSelectorWrapper
    implements Selector
{
    private X509CertSelector _selector;

    public X509CertSelectorWrapper(X509CertSelector selector)
    {
        _selector = selector;
    }

    public boolean match(Object obj)
    {
        if (!(obj instanceof Certificate))
        {
            return false;
        }
        return _selector.match((Certificate)obj);
    }
}
