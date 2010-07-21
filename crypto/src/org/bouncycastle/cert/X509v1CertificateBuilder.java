package org.bouncycastle.cert;

import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.operator.ContentSigner;


/**
 * class to produce an X.509 Version 1 certificate.
 */
public class X509v1CertificateBuilder
{
    private V1TBSCertificateGenerator   tbsGen;

    protected X509v1CertificateBuilder(X509Name issuer, BigInteger serial, Date notBefore, Date notAfter, X509Name subject, SubjectPublicKeyInfo publicKeyInfo)
    {
        tbsGen = new V1TBSCertificateGenerator();
        tbsGen.setSerialNumber(new DERInteger(serial));
        tbsGen.setIssuer(issuer);
        tbsGen.setStartDate(new Time(notBefore));
        tbsGen.setEndDate(new Time(notAfter));
        tbsGen.setSubject(subject);
        tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
    }

    /**
     * generate an X509 certificate, based on the current issuer and subject
     * using the passed in signer
     */
    public X509CertificateHolder build(
        ContentSigner signer)
    {
        tbsGen.setSignature(signer.getAlgorithmIdentifier());

        return CertUtils.generateFullCert(signer, tbsGen.generateTBSCertificate());
    }
}