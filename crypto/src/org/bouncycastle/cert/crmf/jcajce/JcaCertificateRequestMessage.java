package org.bouncycastle.cert.crmf.jcajce;

import java.security.Provider;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;

public class JcaCertificateRequestMessage
    extends CertificateRequestMessage
{
    private final CRMFHelper helper;

    private JcaCertificateRequestMessage(CertReqMsg msg, CRMFHelper helper)
    {
        super(msg);
        this.helper = helper;
    }

    public JcaCertificateRequestMessage(CertificateRequestMessage certReqMsg)
    {
        this(certReqMsg.getCertReqMsg(), new DefaultCRMFHelper());
    }

    public JcaCertificateRequestMessage(CertificateRequestMessage certReqMsg, String providerName)
    {
        this(certReqMsg.getCertReqMsg(), new NamedCRMFHelper(providerName));
    }

    public JcaCertificateRequestMessage(CertificateRequestMessage certReqMsg, Provider provider)
    {
        this(certReqMsg.getCertReqMsg(), new ProviderCRMFHelper(provider));
    }

    public X500Principal getSubjectX500Principal()
    {
        X509Name subject = this.getCertTemplate().getSubject();

        if (subject != null)
        {
            return new X500Principal(subject.getDEREncoded());
        }

        return null;
    }

    public PublicKey getPublicKey()
        throws CRMFException
    {
        SubjectPublicKeyInfo subjectPublicKeyInfo = getCertTemplate().getPublicKey();

        if (subjectPublicKeyInfo != null)
        {
            return helper.toPublicKey(subjectPublicKeyInfo);
        }

        return null;
    }
}
