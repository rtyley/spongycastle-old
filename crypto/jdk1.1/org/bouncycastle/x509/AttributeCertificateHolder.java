package org.spongycastle.x509;

import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.DERInteger;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.x509.GeneralName;
import org.spongycastle.asn1.x509.GeneralNames;
import org.spongycastle.asn1.x509.IssuerSerial;
import org.spongycastle.jce.PrincipalUtil;
import org.spongycastle.jce.X509Principal;

import java.io.IOException;

import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;


/**
 * The Holder object.
 * <pre>
 *  Holder ::= SEQUENCE {
 *        baseCertificateID   [0] IssuerSerial OPTIONAL,
 *                 -- the issuer and serial number of
 *                 -- the holder's Public Key Certificate
 *        entityName          [1] GeneralNames OPTIONAL,
 *                 -- the name of the claimant or role
 *        objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
 *                 -- used to directly authenticate the holder,
 *                 -- for example, an executable
 *  }
 * </pre>
 */
public class AttributeCertificateHolder 
    implements CertSelector
{
    org.spongycastle.asn1.x509.Holder   holder;

    AttributeCertificateHolder(
        ASN1Sequence seq)
    {
        holder = org.spongycastle.asn1.x509.Holder.getInstance(seq);
    }

    public AttributeCertificateHolder(
        X509Certificate cert) 
        throws CertificateParsingException
    {        
        X509Principal   name;
        
        try
        {
            name = PrincipalUtil.getIssuerX509Principal(cert);
        }
        catch (Exception e)
        {
            throw new CertificateParsingException(e.getMessage());
        }
        
        holder = new org.spongycastle.asn1.x509.Holder(new IssuerSerial(new GeneralNames(new DERSequence(new GeneralName(new X509Principal(name)))), new DERInteger(cert.getSerialNumber())));
    }
    
    public AttributeCertificateHolder(
        X509Principal principal) 
    {        
        holder = new org.spongycastle.asn1.x509.Holder(new GeneralNames(new DERSequence(new GeneralName(principal))));
    }
    
    private boolean matchesDN(X509Principal subject, GeneralNames targets)
    {
        GeneralName[]   names = targets.getNames();

        for (int i = 0; i != names.length; i++)
        {
            GeneralName gn = names[i];

            if (gn.getTagNo() == 4)
            {
                try
                {
                    if (new X509Principal(((ASN1Encodable)gn.getName()).getEncoded()).equals(subject))
                    {
                        return true;
                    }
                }
                catch (IOException e)
                {
                }
            }
        }

        return false;
    }

    /* (non-Javadoc)
     * @see java.security.cert.CertSelector#clone()
     */
    public Object clone()
    {
        return new AttributeCertificateHolder((ASN1Sequence)holder.toASN1Object());
    }

    /* (non-Javadoc)
     * @see java.security.cert.CertSelector#match(java.security.cert.Certificate)
     */
    public boolean match(Certificate cert)
    {
        if (!(cert instanceof X509Certificate))
        {
            return false;
        }
        
        X509Certificate x509Cert = (X509Certificate)cert;
        
        try
        {
            if (holder.getBaseCertificateID() != null)
            {
                if (holder.getBaseCertificateID().getSerial().getValue().equals(x509Cert.getSerialNumber())
                    && matchesDN(PrincipalUtil.getIssuerX509Principal(x509Cert), holder.getBaseCertificateID().getIssuer()))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
    
            if (holder.getEntityName() != null)
            {
                if (matchesDN(PrincipalUtil.getSubjectX509Principal(x509Cert), holder.getEntityName()))
                {
                    return true;
                }
            }
        }
        catch (CertificateEncodingException e)
        {
            return false;
        }
        
        /**
         * objectDigestInfo not supported
         */
        return false;
    }
}
