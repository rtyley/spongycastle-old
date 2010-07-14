package org.bouncycastle.cert.crmf;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;

public class CertificateRequestMessage
{
    private final CertReqMsg certReqMsg;

    public CertificateRequestMessage(CertReqMsg certReqMsg)
    {
        this.certReqMsg = certReqMsg;
    }

    public X509Name getSubject()
    {
        return this.certReqMsg.getCertReq().getCertTemplate().getSubject();
    }

    public SubjectPublicKeyInfo getPublicKey()
        throws InvalidKeyException, NoSuchAlgorithmException
    {
        return this.certReqMsg.getCertReq().getCertTemplate().getPublicKey();
    }
}