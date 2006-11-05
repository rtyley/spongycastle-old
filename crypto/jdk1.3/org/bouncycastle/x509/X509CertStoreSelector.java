package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import org.bouncycastle.jce.cert.X509CertSelector;
import java.security.cert.Certificate;

public class X509CertSelectorWrapper
    extends X509CertSelector
    implements Selector
{
    public boolean match(Object obj)
    {
        if (!(obj instanceof Certificate))
        {
            return false;
        }

        return this.match((Certificate)obj);
    }
}
