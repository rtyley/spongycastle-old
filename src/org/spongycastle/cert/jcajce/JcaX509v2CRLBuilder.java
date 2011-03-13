package org.spongycastle.cert.jcajce;

import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.cert.X509v2CRLBuilder;

public class JcaX509v2CRLBuilder
    extends X509v2CRLBuilder
{
    public JcaX509v2CRLBuilder(X500Principal issuer, Date now)
    {
        super(X500Name.getInstance(issuer.getEncoded()), now);
    }
}
