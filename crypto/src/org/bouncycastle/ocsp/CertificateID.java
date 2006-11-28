package org.bouncycastle.ocsp;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509Principal;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class CertificateID
{
    public static final String HASH_SHA1 = "1.3.14.3.2.26";

    private CertID  id;

    public CertificateID(
        CertID id)
    {
        this.id = id;
    }

    /**
     * create from an issuer certificate and the serial number of the
     * certificate it signed.
     * @exception OCSPException if any problems occur creating the id fields.
     */
    public CertificateID(
        String          hashAlgorithm,
        X509Certificate issuerCert,
        BigInteger      number,
        String          provider)
        throws OCSPException
    {
        try
        {
            MessageDigest       digest = MessageDigest.getInstance(hashAlgorithm, provider);
            AlgorithmIdentifier hashAlg = new AlgorithmIdentifier(
                                        new DERObjectIdentifier(hashAlgorithm), new DERNull());

            X509Principal issuerName = PrincipalUtil.getSubjectX509Principal(issuerCert);

            digest.update(issuerName.getEncoded());

            ASN1OctetString issuerNameHash = new DEROctetString(digest.digest());
            PublicKey issuerKey = issuerCert.getPublicKey();


            ASN1InputStream aIn = new ASN1InputStream(issuerKey.getEncoded());
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(
                                                            aIn.readObject());

            digest.update(info.getPublicKeyData().getBytes());

            ASN1OctetString issuerKeyHash = new DEROctetString(digest.digest());

            DERInteger serialNumber = new DERInteger(number);

            this.id = new CertID(hashAlg, issuerNameHash,
                                            issuerKeyHash, serialNumber);
        }
        catch (Exception e)
        {
            throw new OCSPException("problem creating ID: " + e, e);
        }
    }

    /**
     * create using the BC provider
     */
    public CertificateID(
        String          hashAlgorithm,
        X509Certificate issuerCert,
        BigInteger      number)
        throws OCSPException
    {
        this(hashAlgorithm, issuerCert, number, "BC");
    }

    public String getHashAlgOID()
    {
        return id.getHashAlgorithm().getObjectId().getId();
    }

    public byte[] getIssuerNameHash()
    {
        return id.getIssuerNameHash().getOctets();
    }

    public byte[] getIssuerKeyHash()
    {
        return id.getIssuerKeyHash().getOctets();
    }

    /**
     * return the serial number for the certificate associated
     * with this request.
     */
    public BigInteger getSerialNumber()
    {
        return id.getSerialNumber().getValue();
    }

    public CertID toASN1Object()
    {
        return id;
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof CertificateID))
        {
            return false;
        }

        CertificateID   obj = (CertificateID)o;

        return id.getDERObject().equals(obj.id.getDERObject());
    }

    public int hashCode()
    {
        return id.getDERObject().hashCode();
    }
}
