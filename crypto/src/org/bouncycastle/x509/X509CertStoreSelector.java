package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;

public class X509CertStoreSelector
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
