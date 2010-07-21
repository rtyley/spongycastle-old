package org.bouncycastle.cert.jcajce;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;

public class JcaX509CertificateConverter
{
    private CertHelper helper = new DefaultCertHelper();

    public JcaX509CertificateConverter()
    {
        this.helper = new DefaultCertHelper();
    }

    public JcaX509CertificateConverter setProvider(Provider provider)
    {
        this.helper = new ProviderCertHelper(provider);

        return this;
    }

    public JcaX509CertificateConverter setProvider(String providerName)
    {
        this.helper = new NamedCertHelper(providerName);

        return this;
    }

    public X509Certificate getCertificate(X509CertificateHolder certHolder)
        throws CertificateException
    {
        try
        {
            CertificateFactory cFact = helper.getCertificateFactory("X.509");

            return (X509Certificate)cFact.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
        }
        catch (IOException e)
        {
            throw new CertificateParsingException("exception parsing certificate: " + e.getMessage(), e);
        }
        catch (NoSuchProviderException e)
        {
            throw new CertificateException("cannot find required provider:" + e.getMessage(), e);
        }
    }
}