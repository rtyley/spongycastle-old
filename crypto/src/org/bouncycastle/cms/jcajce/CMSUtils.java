package org.bouncycastle.cms.jcajce;

import java.security.Key;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.operator.GenericKey;

class CMSUtils
{
    static TBSCertificateStructure getTBSCertificateStructure(
        X509Certificate cert)
        throws CertificateEncodingException
    {
            return TBSCertificateStructure.getInstance(cert.getTBSCertificate());
    }

    static Key getJceKey(GenericKey key)
    {
        if (key.getRepresentation() instanceof Key)
        {
            return (Key)key.getRepresentation();
        }

        if (key.getRepresentation() instanceof byte[])
        {
            return new SecretKeySpec((byte[])key.getRepresentation(), "ENC");
        }

        throw new IllegalArgumentException("unknown generic key type");
    }

    static IssuerAndSerialNumber getIssuerAndSerialNumber(X509Certificate cert)
        throws CertificateEncodingException
    {
        X509CertificateStructure certStruct = X509CertificateStructure.getInstance(cert.getEncoded());

        return new IssuerAndSerialNumber(certStruct.getIssuer(), cert.getSerialNumber());
    }


    static byte[] getSubjectKeyId(X509Certificate cert)
    {
        byte[] ext = cert.getExtensionValue(X509Extension.subjectKeyIdentifier.getId());

        if (ext != null)
        {
            return ASN1OctetString.getInstance(ASN1OctetString.getInstance(ext).getOctets()).getOctets();
        }
        else
        {
            return null;
        }
    }

    static EnvelopedDataHelper createContentHelper(Provider provider)
    {
        if (provider != null)
        {
            return new EnvelopedDataHelper(new ProviderJcaJceHelper(provider));
        }
        else
        {
            return new EnvelopedDataHelper(new DefaultJcaJceHelper());
        }
    }

    static EnvelopedDataHelper createContentHelper(String providerName)
    {
        if (providerName != null)
        {
            return new EnvelopedDataHelper(new NamedJcaJceHelper(providerName));
        }
        else
        {
            return new EnvelopedDataHelper(new DefaultJcaJceHelper());
        }
    }

}