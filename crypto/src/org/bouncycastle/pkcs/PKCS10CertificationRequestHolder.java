package org.bouncycastle.pkcs;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;

/**
 * Holding class for a PKCS#10 certification request.
 */
public class PKCS10CertificationRequestHolder
{
    private CertificationRequest certificationRequest;

    private static CertificationRequest parseBytes(byte[] encoding)
        throws IOException
    {
        try
        {
            return CertificationRequest.getInstance(ASN1Object.fromByteArray(encoding));
        }
        catch (ClassCastException e)
        {
            throw new PKCSIOException("malformed data: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new PKCSIOException("malformed data: " + e.getMessage(), e);
        }
    }
    
    public PKCS10CertificationRequestHolder(CertificationRequest certificationRequest)
    {
         this.certificationRequest = certificationRequest;
    }

    /**
     * Create a PKCS10CertificationRequestHolder from the passed in bytes.
     *
     * @param encoded BER/DER encoding of the CertificationRequest structure.
     * @throws IOException in the event of corrupted data, or an incorrect structure.
     */
    public PKCS10CertificationRequestHolder(byte[] encoded)
        throws IOException
    {
        this(parseBytes(encoded));
    }

    public CertificationRequest toASN1Structure()
    {
         return certificationRequest;
    }

    public X500Name getSubject()
    {
        return X500Name.getInstance(certificationRequest.getCertificationRequestInfo().getSubject());
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return certificationRequest.getSignatureAlgorithm();
    }

    public byte[] getSignature()
    {
        return certificationRequest.getSignature().getBytes();
    }
    
    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return certificationRequest.getCertificationRequestInfo().getSubjectPublicKeyInfo();
    }

    public byte[] getEncoded()
        throws IOException
    {
        return certificationRequest.getEncoded();
    }

    /**
     * Validate the signature on the PKCS10 certification request in this holder.
     *
     * @param verifierProvider a ContentVerifierProvider that can generate a verifier for the signature.
     * @return true if the signature is valid, false otherwise.
     * @throws PKCSException if the signature cannot be processed or is inappropriate.
     */
    public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
        throws PKCSException
    {
        CertificationRequestInfo requestInfo = certificationRequest.getCertificationRequestInfo();

        ContentVerifier verifier;

        try
        {
            verifier = verifierProvider.get(certificationRequest.getSignatureAlgorithm());

            OutputStream sOut = verifier.getOutputStream();

            sOut.write(requestInfo.getDEREncoded());

            sOut.close();
        }
        catch (Exception e)
        {
            throw new PKCSException("unable to process signature: " + e.getMessage(), e);
        }

        return verifier.verify(certificationRequest.getSignature().getBytes());
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof PKCS10CertificationRequestHolder))
        {
            return false;
        }

        PKCS10CertificationRequestHolder other = (PKCS10CertificationRequestHolder)o;

        return this.toASN1Structure().equals(other.toASN1Structure());
    }

    public int hashCode()
    {
        return this.toASN1Structure().hashCode();
    }
}
