package org.bouncycastle.cert.pkcs.jcajce;

import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.pkcs.PKCS10CertificationRequestBuilder;

public class JcaPKCS10CertificationRequestBuilder
    extends PKCS10CertificationRequestBuilder
{
    public JcaPKCS10CertificationRequestBuilder(X509Name subject, PublicKey publicKey)
    {
        super(subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }

    public JcaPKCS10CertificationRequestBuilder(X500Principal subject, PublicKey publicKey)
    {
        super(X509Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
    }
}
