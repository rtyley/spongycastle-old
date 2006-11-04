package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import org.bouncycastle.jce.cert.X509CertSelector;
import java.security.cert.Certificate;

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
        return _selector.match((Certificate)obj);
    }
}
