package org.bouncycastle.crmf;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jcajce.JcaUtils;

public class CertificateRequestMessage
{
    private final CertReqMsg certReqMsg;

    public CertificateRequestMessage(CertReqMsg certReqMsg)
    {
        this.certReqMsg = certReqMsg;
    }

    public X500Principal getSubject()
    {
        X509Name subject = this.certReqMsg.getCertReq().getCertTemplate().getSubject();

        if (subject != null)
        {
            return new X500Principal(subject.getDEREncoded());
        }

        return null;
    }

    public PublicKey getPublicKey()
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        SubjectPublicKeyInfo subjectPublicKeyInfo = this.certReqMsg.getCertReq().getCertTemplate().getPublicKey();

        if (subjectPublicKeyInfo != null)
        {
            return JcaUtils.toPublicKey(subjectPublicKeyInfo);
        }

        return null;
    }
   
    public PublicKey getPublicKey(Provider provider)
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        SubjectPublicKeyInfo subjectPublicKeyInfo = this.certReqMsg.getCertReq().getCertTemplate().getPublicKey();

        if (subjectPublicKeyInfo != null)
        {
            return JcaUtils.toPublicKey(subjectPublicKeyInfo, provider);
        }

        return null;
    }

    public PublicKey getPublicKey(String provider)
        throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException
    {
        SubjectPublicKeyInfo subjectPublicKeyInfo = this.certReqMsg.getCertReq().getCertTemplate().getPublicKey();

        if (subjectPublicKeyInfo != null)
        {
            return JcaUtils.toPublicKey(subjectPublicKeyInfo, provider);
        }

        return null;
    }
}
