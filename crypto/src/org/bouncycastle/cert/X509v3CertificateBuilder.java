package org.bouncycastle.cert;

import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509ExtensionsGenerator;
import org.bouncycastle.operator.ContentSigner;


/**
 * class to produce an X.509 Version 3 certificate.
 */
public class X509v3CertificateBuilder
{
    private V3TBSCertificateGenerator   tbsGen;
    private X509ExtensionsGenerator     extGenerator;

    public X509v3CertificateBuilder(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
    {
        tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(new DERInteger(serial));
        tbsGen.setIssuer(issuer);
        tbsGen.setStartDate(new Time(notBefore));
        tbsGen.setEndDate(new Time(notAfter));
        tbsGen.setSubject(subject);
        tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);

        extGenerator = new X509ExtensionsGenerator();
    }

    /**
     * Set the subject unique ID - note: it is very rare that it is correct to do this.
     */
    public X509v3CertificateBuilder setSubjectUniqueID(boolean[] uniqueID)
    {
        tbsGen.setSubjectUniqueID(booleanToBitString(uniqueID));

        return this;
    }

    /**
     * Set the issuer unique ID - note: it is very rare that it is correct to do this.
     */
    public X509v3CertificateBuilder setIssuerUniqueID(boolean[] uniqueID)
    {
        tbsGen.setIssuerUniqueID(booleanToBitString(uniqueID));

        return this;
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     */
    public X509v3CertificateBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean critical,
        ASN1Encodable value)
    {
        extGenerator.addExtension(oid, critical, value);

        return this;
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     * copying the extension value from another certificate.
     */
    public X509v3CertificateBuilder copyAndAddExtension(
        ASN1ObjectIdentifier oid,
        boolean critical,
        X509CertificateHolder certHolder)
    {
        X509CertificateStructure cert = certHolder.toASN1Structure();

        X509Extension extension = cert.getTBSCertificate().getExtensions().getExtension(oid);

        if (extension == null)
        {
            throw new NullPointerException("extension " + oid + " not present");
        }

        extGenerator.addExtension(oid, critical, extension.getValue().getOctets());

        return this;
    }

    /**
     * generate an X509 certificate, based on the current issuer and subject
     * using the passed in signer
     */
    public X509CertificateHolder build(
        ContentSigner signer)
    {
        tbsGen.setSignature(signer.getAlgorithmIdentifier());

        if (!extGenerator.isEmpty())
        {
            tbsGen.setExtensions(extGenerator.generate());
        }

        return CertUtils.generateFullCert(signer, tbsGen.generateTBSCertificate());
    }

    private DERBitString booleanToBitString(boolean[] id)
    {
        byte[] bytes = new byte[(id.length + 7) / 8];

        for (int i = 0; i != id.length; i++)
        {
            bytes[i / 8] |= (id[i]) ? (1 << ((7 - (i % 8)))) : 0;
        }

        int pad = id.length % 8;

        if (pad == 0)
        {
            return new DERBitString(bytes);
        }
        else
        {
            return new DERBitString(bytes, 8 - pad);
        }
    }
}