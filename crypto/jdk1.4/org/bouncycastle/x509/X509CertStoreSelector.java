package org.bouncycastle.x509;

import org.bouncycastle.util.Selector;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.X509CertSelector;

import javax.security.auth.x500.X500Principal;

/**
 * This class is a Selector implementation for X.509 certificates.
 * 
 * @see org.bouncycastle.util.Selector
 * @see org.bouncycastle.x509.X509Store
 * @see org.bouncycastle.jce.provider.X509StoreCertCollection
 */
public class X509CertStoreSelector extends X509CertSelector implements Selector
{

    public boolean match(Object obj)
    {
        if (!(obj instanceof Certificate))
        {
            return false;
        }

        return super.match((Certificate)obj);
    }

    public X500Principal getSubject()
    {
        try
        {
            byte[] enc = getSubjectAsBytes();

            if (enc != null)
            {
                return new X500Principal(enc);
            }
        }
        catch (IOException e)
        {
            throw new IllegalStateException("badly encoded subject");
        }

        return null;
    }

    public X500Principal getIssuer()
    {
        try
        {
            byte[] enc = getIssuerAsBytes();

            if (enc != null)
            {
                return new X500Principal(enc);
            }
        }
        catch (IOException e)
        {
            throw new IllegalStateException("badly encoded issuer");
        }

        return null;
    }

    /**
     * Returns an instance of this from a <code>X509CertSelector</code>.
     *
     * @param selector A <code>X509CertSelector</code> instance.
     * @return An instance of an <code>X509CertStoreSelector</code>.
     * @exception IllegalArgumentException if selector is null or creation fails.
     */
    public static X509CertStoreSelector getInstance(X509CertSelector selector)
    {
        if (selector == null)
        {
            throw new IllegalArgumentException("cannot create from null selector");
        }
        X509CertStoreSelector cs = new X509CertStoreSelector();
        cs.setAuthorityKeyIdentifier(selector.getAuthorityKeyIdentifier());
        cs.setBasicConstraints(selector.getBasicConstraints());
        cs.setCertificate(selector.getCertificate());
        cs.setCertificateValid(selector.getCertificateValid());
        try
        {
            cs.setExtendedKeyUsage(selector.getExtendedKeyUsage());
            cs.setNameConstraints(selector.getNameConstraints());
            cs.setPathToNames(selector.getPathToNames());
            cs.setPolicy(selector.getPolicy());
            cs.setSubjectPublicKeyAlgID(selector.getSubjectPublicKeyAlgID());
            cs.setIssuer(selector.getIssuerAsBytes());
            cs.setSubject(selector.getSubjectAsBytes());
        }
        catch (IOException e)
        {
            // cannot happen
            throw new IllegalArgumentException(e.getMessage());
        }
        cs.setKeyUsage(selector.getKeyUsage());
        cs.setMatchAllSubjectAltNames(selector.getMatchAllSubjectAltNames());
        cs.setPrivateKeyValid(selector.getPrivateKeyValid());
        cs.setSerialNumber(selector.getSerialNumber());
        cs.setSubjectKeyIdentifier(selector.getSubjectKeyIdentifier());
        cs.setSubjectPublicKey(selector.getSubjectPublicKey());
        return cs;
    }
}
