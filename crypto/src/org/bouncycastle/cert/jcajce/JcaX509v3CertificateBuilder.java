package org.bouncycastle.cert.jcajce;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;

public class JcaX509v3CertificateBuilder
    extends X509v3CertificateBuilder
{
    public JcaX509v3CertificateBuilder(X509Name issuer, BigInteger serial, Date notBefore, Date notAfter, X509Name subject, PublicKey publicKey)
    {
        super(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    public JcaX509v3CertificateBuilder(X500Principal issuer, BigInteger serial, Date notBefore, Date notAfter, X500Principal subject, PublicKey publicKey)
    {
        super(X509Name.getInstance(issuer.getEncoded()), serial, notBefore, notAfter, X509Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    public JcaX509v3CertificateBuilder(X509Certificate issuerCert, BigInteger serial, Date notBefore, Date notAfter, X500Principal subject, PublicKey publicKey)
    {
        super(X509Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded()), serial, notBefore, notAfter, X509Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     * copying the extension value from another certificate.
     */
    public JcaX509v3CertificateBuilder copyAndAddExtension(
        ASN1ObjectIdentifier oid,
        boolean critical,
        X509Certificate certificate)
        throws CertificateEncodingException
    {
        this.copyAndAddExtension(oid, critical, new JcaX509CertificateHolder(certificate));

        return this;
    }
}